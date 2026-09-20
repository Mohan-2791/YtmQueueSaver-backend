import os
import json
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
import requests
from ytmusicapi import YTMusic, OAuthCredentials

logger = logging.getLogger("ytm_saver.service")

# Cap concurrent requests to YouTube's API so we don't trip rate limits
# on very large playlists while still being drastically faster than
# one-request-at-a-time.
MAX_CONCURRENT_ADDS = 8


class YTMService:
    def __init__(self, token_data: dict):
        self.token_data = token_data
        self.client_id = os.getenv("YTM_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.getenv("YTM_CLIENT_SECRET", "")

        # If your Google OAuth client is a "confidential" client type (as
        # opposed to a public/installed client), ytmusicapi's OAuth flow
        # needs the client secret to refresh tokens. An empty value here
        # won't necessarily break anything (public clients don't need one),
        # but if restores start failing with auth errors in production and
        # this is empty, check your OAuth client type first.
        if not self.client_secret:
            logger.warning(
                "YTM_CLIENT_SECRET is not set. This is fine for a public/installed OAuth "
                "client, but if your Google OAuth client is a confidential client type, "
                "token refresh during playlist restore will fail."
            )

    def _add_single_track(self, items_url: str, headers: dict, playlist_id: str, video_id: str) -> None:
        """Adds one track to the playlist. Raises nothing on failure — logs and
        returns, matching the previous best-effort behavior (one bad video ID
        shouldn't sink the whole restore)."""
        try:
            item_payload = {
                "snippet": {
                    "playlistId": playlist_id,
                    "resourceId": {
                        "kind": "youtube#video",
                        "videoId": video_id,
                    },
                }
            }
            item_resp = requests.post(items_url, headers=headers, json=item_payload, timeout=8)
            if not item_resp.ok:
                logger.warning("Failed to append track %s to playlist %s: %s", video_id, playlist_id, item_resp.text)
        except Exception as item_err:
            logger.warning("Exception appending track %s: %s", video_id, item_err)

    def _restore_via_youtube_data_api(
        self, title: str, tracks: List[Dict], playback_mode: str, access_token: str
    ) -> str:
        """
        Creates a playlist directly in the user's YouTube / YouTube Music personal account
        using the user's Google OAuth Bearer access token via official YouTube Data API v3.

        Track-adding is parallelized (bounded by MAX_CONCURRENT_ADDS) since YouTube's API
        has no batch "add many videos" endpoint — sequential one-at-a-time calls were the
        reason large restores took 15-25+ seconds and blew past client-side timeouts.
        """
        description = f"Restored via YTM Queue Saver ({playback_mode} Mode)"

        # 1. Create playlist
        url = "https://www.googleapis.com/youtube/v3/playlists?part=snippet,status"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "snippet": {
                "title": title,
                "description": description,
            },
            "status": {
                "privacyStatus": "private",
            },
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if not resp.ok:
            raise RuntimeError(f"YouTube Data API playlist creation failed: {resp.status_code} - {resp.text}")

        playlist_data = resp.json()
        playlist_id = playlist_data.get("id")
        if not playlist_id:
            raise RuntimeError("YouTube API response missing playlist ID")

        # 2. Add tracks to playlist CONCURRENTLY instead of one-by-one
        items_url = "https://www.googleapis.com/youtube/v3/playlistItems?part=snippet"
        video_ids = [t["videoId"] for t in tracks if isinstance(t, dict) and t.get("videoId")]

        if video_ids:
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_ADDS) as executor:
                futures = [
                    executor.submit(self._add_single_track, items_url, headers, playlist_id, video_id)
                    for video_id in video_ids
                ]
                # Drain futures so we don't return before all adds have at least
                # attempted (errors are already swallowed/logged inside the task).
                for future in as_completed(futures):
                    future.result()

        return playlist_id

    def _get_ytmusic_instance(self) -> Tuple[YTMusic, str]:
        """
        Creates an authenticated YTMusic client using a secure short-lived temporary credentials file.

        NOTE: ytmusicapi's OAuth support (OAuthCredentials/RefreshingToken) requires a
        full token set - access_token, refresh_token, scope, token_type, expires_at -
        the kind you get from a server-side authorization-code exchange. Tokens
        acquired via chrome.identity.getAuthToken() are access-token-only; Chrome
        manages refresh internally and never exposes a refresh_token to the app. So
        this fallback is only usable if token_data actually came from a full OAuth
        exchange. If it didn't, fail with a clear message instead of letting
        ytmusicapi raise an opaque TypeError deep in its own constructor.
        """
        required_fields = ("refresh_token", "scope", "token_type")
        missing = [f for f in required_fields if not self.token_data.get(f)]
        if missing:
            raise RuntimeError(
                f"Cannot use the ytmusicapi fallback: token_data is missing {missing}. "
                "This is expected when the access token came from "
                "chrome.identity.getAuthToken(), which does not provide a refresh "
                "token. The YouTube Data API v3 path (using the access_token directly) "
                "is the only usable restore path for these tokens - check why that path "
                "failed rather than relying on this fallback."
            )

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        try:
            os.chmod(temp_path, 0o600)
            with os.fdopen(fd, "w") as temp_file:
                json.dump(self.token_data, temp_file)

            yt = YTMusic(
                temp_path,
                oauth_credentials=OAuthCredentials(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                ),
            )
            return yt, temp_path
        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise RuntimeError(f"Failed to initialize YouTube Music client: {str(e)}")

    def restore_playlist(self, title: str, tracks: List[Dict], playback_mode: str) -> str:
        """
        Materializes a saved snapshot directly into the user's YouTube Music personal account.
        Tries direct official YouTube Data API v3 first if access_token is present,
        falling back to ytmusicapi.
        """
        access_token = self.token_data.get("access_token")
        if access_token:
            try:
                logger.info("Attempting playlist creation via YouTube Data API v3...")
                return self._restore_via_youtube_data_api(
                    title=title,
                    tracks=tracks,
                    playback_mode=playback_mode,
                    access_token=access_token,
                )
            except Exception as api_err:
                logger.warning("YouTube Data API restore failed, falling back to ytmusicapi: %s", api_err)

        # Fallback to ytmusicapi
        yt, temp_path = self._get_ytmusic_instance()
        try:
            description = f"Restored via YTM Queue Saver ({playback_mode} Mode)"
            playlist_id = yt.create_playlist(title=title, description=description)

            video_ids = [t["videoId"] for t in tracks if isinstance(t, dict) and t.get("videoId")]
            if video_ids:
                yt.add_playlist_items(playlist_id, video_ids)

            return playlist_id
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)