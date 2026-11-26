"""Geography helpers: city coordinates and great-circle distance.

Used for impossible-travel detection: if the same account logs in from two places
farther apart than a plane could fly in the time between, one login is not the user.
"""
from math import asin, cos, radians, sin, sqrt

# name: (latitude, longitude, ISO country code)
CITIES = {
    "San Jose": (37.34, -121.89, "US"), "Los Angeles": (34.05, -118.24, "US"),
    "Seattle": (47.61, -122.33, "US"), "Austin": (30.27, -97.74, "US"),
    "Chicago": (41.88, -87.63, "US"), "New York": (40.71, -74.01, "US"),
    "Boston": (42.36, -71.06, "US"), "Atlanta": (33.75, -84.39, "US"),
    "Denver": (39.74, -104.99, "US"), "Miami": (25.76, -80.19, "US"),
    "Toronto": (43.65, -79.38, "CA"), "London": (51.51, -0.13, "GB"),
    "Amsterdam": (52.37, 4.90, "NL"), "Frankfurt": (50.11, 8.68, "DE"),
    "Moscow": (55.76, 37.62, "RU"), "Beijing": (39.90, 116.40, "CN"),
    "Shenzhen": (22.54, 114.06, "CN"), "Seoul": (37.57, 126.98, "KR"),
    "Mumbai": (19.08, 72.88, "IN"), "Sao Paulo": (-23.55, -46.63, "BR"),
    "Lagos": (6.52, 3.38, "NG"), "Tehran": (35.69, 51.39, "IR"),
    "Hanoi": (21.03, 105.85, "VN"), "Kyiv": (50.45, 30.52, "UA"),
    "Singapore": (1.35, 103.82, "SG"), "Tokyo": (35.68, 139.69, "JP"),
}

EARTH_RADIUS_KM = 6371.0
MAX_TRAVEL_KMH = 900.0  # roughly a commercial jet; anything faster is impossible


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Distance between two points on Earth's surface (the 'great-circle' distance)."""
    lat1, lon1, lat2, lon2 = map(radians, (lat1, lon1, lat2, lon2))
    a = sin((lat2 - lat1) / 2) ** 2 + cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2) ** 2
    return 2 * EARTH_RADIUS_KM * asin(sqrt(a))
