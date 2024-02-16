# Cylance hashlookup

Cylance hash lookup enables you to query possible infected clients of yours using a SHA256 hash. 
The response includes information about the matching sample(s) along with information about affected clients.

# FAQ

### Q: Why only SHA256
Sadly, although the response data contains an MD5 hash, the API only allows you to query with a SHA256
