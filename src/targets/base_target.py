import abc
from typing import List, Set, Optional

class BaseTarget(abc.ABC):
    """
    Abstract base class for different download targets.
    """

    @abc.abstractmethod
    async def get_target_name(self) -> str:
        """
        Returns the machine-friendly name of the target (e.g., "project_gutenberg").
        """
        pass

    @abc.abstractmethod
    async def discover_links(self, downloaded_urls: Set[str], keyword_filters: Optional[List[str]] = None) -> List[str]:
        """
        Discovers new download links from the target source.

        Args:
            downloaded_urls: A set of URLs that have already been downloaded and processed.
                             This is used to avoid re-downloading content.
            keyword_filters: An optional list of keywords to filter discoverable items.
                             If None or empty, no keyword filtering is applied.

        Returns:
            A list of unique string URLs that are new and match filters (if any).
        """
        pass
