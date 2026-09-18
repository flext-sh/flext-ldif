# from flext-ldif/docs/troubleshooting.md:405
# Error in chain composition
result = (
    api
    .parse_file(file_path)
    .flat_map(api.validate_entries)  # Error: expects bool, gets list
    .flat_map(api.filter_persons)
)```
**Solution**:

