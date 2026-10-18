"""Ordered registry of assessment areas."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from vulpnix.engine.area import Area


class AreaRegistry:
    """Areas in the order they are presented, looked up by id."""

    def __init__(self, areas: Iterable[Area] = ()) -> None:
        self._areas: dict[str, Area] = {}
        for area in areas:
            self.register(area)

    def register(self, area: Area) -> None:
        if not isinstance(area, Area):
            raise TypeError(f"{area!r} does not implement the Area contract.")
        if area.id in self._areas:
            raise ValueError(f"Area {area.id!r} is already registered.")
        self._areas[area.id] = area

    def get(self, area_id: str) -> Area:
        try:
            return self._areas[area_id]
        except KeyError:
            raise KeyError(f"Unknown area: {area_id!r}") from None

    def ids(self) -> tuple[str, ...]:
        return tuple(self._areas)

    def __iter__(self) -> Iterator[Area]:
        return iter(self._areas.values())

    def __len__(self) -> int:
        return len(self._areas)

    def __contains__(self, area_id: object) -> bool:
        return area_id in self._areas
