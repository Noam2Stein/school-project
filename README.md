# `school-project`

A school project i am *forced* to make. This project *does not* live up to my
programming standards.

A client server app that lets users encrypt data in groups... so that a group of
people can encrypt their data together then everybody needs to release their
lock so that everybody can access the data...

Im not too sure how useful this is, though maybe if they drug you and get your
password (like in that meme!) and a copy of the server then its useful because
they need to catch and drug all of your friends too if they want the data.

This project uses these anti-patterns:

- Python
- Garbage Collection
- Implicit Shared References
- Classes
- Inheritence
- Exceptions

This is supposed to be a secure application but who knows if its actually
possible to build a secure application in Python. Obvious vulnerabilities
are:

- The classic "to deserialize run whatever constructor the data tells you
  to" RCE

- Non atomic mutations to the database

- Sending the server too much
  data in the right place will most likely crash it

## Why name it "school project"

school-project: Unlocking Collective Security

Imagine a digital space where privacy and collaboration come together seamlessly. school-project is a cutting-edge client-server app built for groups who want to keep their data secure together. Here’s how it works: groups of users encrypt their data, each adding their own layer of security. But here's the catch—only when everyone in the group releases their lock can the data be fully accessed. Think of it as a collective vault, where trust and teamwork make the contents accessible.

The name "school-project"? It’s not just a label—it’s a reminder of collaboration and problem-solving at its finest. In a way, it feels like the kind of project you'd dive into during school, but one that tackles real-world encryption and security challenges, designed for a group that values both protection and shared responsibility.

Secure your data, share the responsibility, and unlock it only when everyone is ready. Whether you’re collaborating on a personal project, a business, or anything in between, school-project keeps your group’s data safe, together.

Does this resonate with the vibe you're going for?
