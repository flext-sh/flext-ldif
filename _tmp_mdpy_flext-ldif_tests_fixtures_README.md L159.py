# from flext-ldif/tests/fixtures/README.md:159
from tests import FixtureCoverageReport

coverage = FixtureCoverageReport.generate_summary(all_fixtures)
FixtureCoverageReport.print_coverage_report(coverage)
