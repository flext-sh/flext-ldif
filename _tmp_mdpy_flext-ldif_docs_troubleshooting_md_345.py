# from flext-ldif_docs/troubleshooting.md:345
# Error: "Service registration failed"
container = FlextContainer.get_global()
result = container.bind("ldif_api", api)
# result.failure == True```
**Solution**:

