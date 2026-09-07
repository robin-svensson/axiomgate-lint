"""The same crew with delegation left alone. The linter should stay quiet.

Run it from the repository root:

    axiomgate-lint examples/safe_crew.py

Expected: no findings, and exit code 0.

Both agents rely on CrewAI's own default, `allow_delegation=False`. Writing
it out, as `writer` does, is not required. It is a reasonable habit when a
codebase has agents that do delegate, because it makes the difference between
them visible in review rather than implied by an absence.
"""
from crewai import Agent, Crew, Task


researcher = Agent(
    role="Researcher",
    goal="Find and summarise sources",
    backstory="Reads widely and quickly.",
)


writer = Agent(
    role="Writer",
    goal="Turn findings into a brief",
    backstory="Writes plainly.",
    allow_delegation=False,
)


crew = Crew(
    agents=[researcher, writer],
    tasks=[
        Task(description="Research the topic", agent=researcher, expected_output="Notes"),
        Task(description="Write the brief", agent=writer, expected_output="Brief"),
    ],
)
