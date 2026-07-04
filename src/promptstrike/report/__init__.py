"""Report generation: render triaged findings into HTML and Markdown reports.

``report.reporter.render_report`` consumes ``TriagedFinding`` objects and produces
a self-contained dark-theme HTML report or a GitHub-flavoured Markdown report.
Pure presentation — no scanning or scoring logic lives here.
"""
