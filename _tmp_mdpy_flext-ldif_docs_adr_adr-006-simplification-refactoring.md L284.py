# from flext-ldif/docs/adr/adr-006-simplification-refactoring.md:284
def parse(
    self, source, server_type="rfc", *, batch=False, paginate=False, page_size=1000
):
    if batch and not isinstance(source, list):
        ...
        # 50 lines
    if paginate and isinstance(source, list):
        ...
        # 35 lines
    # 40 lines single source```
**After** (80 lines with pattern matching):

