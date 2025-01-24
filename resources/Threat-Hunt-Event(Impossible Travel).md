# Threat Event: Impossible Travel - Anomalous Login Locations

## Scenario Overview
A "Bad Actor" attempts to access an account from a geographically distant location in a short timeframe, simulating impossible travel.

### Steps Taken by "Bad Actor":
1. **Initial Login:**
   - Login from your VM using your current IP.
   - Access a web service or application using your credentials.
2. **Simulated Travel:**
   - Use a VPN or proxy to switch to a different geographic location (e.g., the US, Europe).
   - Perform another login attempt on the same service/application.
3. **Post-Attack Behavior:**
   - Attempt sensitive actions (e.g., modify user settings, view confidential data).
   - Logout after completing suspicious activity.

---

## Tables Used to Detect IoCs:

| **Table**         | **Description**                                                                                     |
|-------------------|-----------------------------------------------------------------------------------------------------|
| **SigninLogs**     | Provides login records, including IP addresses, locations, and timestamps.                        |
| **AzureActivity**  | Tracks user and administrative activities within Azure.                                            |

---

## Detection Queries:

### Impossible Travel Detection
```kql
SigninLogs
| summarize Locations = make_set(Location), LoginCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| extend Distance = geo_distance_2points(set_element(Locations, 0), set_element(Locations, 1)) // If location data includes latitude/longitude
| where Distance > 5000 // Distance in kilometers indicating impossible travel
| project TimeGenerated, UserPrincipalName, Locations, LoginCount

```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47/
- **Date**: January 24, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**
