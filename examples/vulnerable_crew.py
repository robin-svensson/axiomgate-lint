"""A CrewAI crew with delegation switched on. The linter should flag this.

Run it from the repository root:

    axiomgate-lint examples/vulnerable_crew.py

Expected: one HIGH finding, AG-DEL-001, and exit code 2.

Nothing here is executed by the linter, and nothing here should be copied
into a real project. It exists so you can confirm the tool works before you
trust a clean result on your own code.
"""
from crewai import Agent, Crew, Task


# The finding. `allow_delegation=True` lets this agent hand work to any other
# agent in the crew, which can hand it on again. There is no depth limit and
# nobody is asked to approve a hop.
researcher = Agent(
    role="Researcher",
    goal="Find and summarise sources",
    backstory="Reads widely and quickly.",
    allow_delegation=True,
)


# Same agent, delegation left at the CrewAI default of False. Not flagged.
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
