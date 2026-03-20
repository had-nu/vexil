# Detecting Developer Error vs. Adversary Action
*Why Static Secret Scanning Has a Narrower Threat Model Than You Think — And Why That's Fine*

## The Inflated Framing of Secret Detection

In the security industry, secret detection is frequently marketed as a core pillar of "Supply Chain Security." While technically true—secrets in source control are a known vector—this framing often inflates the expectations of what a static scanner can actually achieve.

Most high-precision secret scanners (including Vexil) operate at the level of **static text analysis**. They are designed to find strings that look like credentials. By design, this control is most effective at blocking a specific class of risk: **The Accidental Developer Error.**

## The Developer Error Vector

A developer, under pressure to meet a deadline, hardcodes a database password "just for testing" and accidentally commits it. Or they include an active AWS Access Key in a local configuration file that gets swallowed by a `git add .` command.

This is a human-centric failure. The "adversary" in this scenario isn't a state-sponsored actor with a 0-day; it is a tired engineer making a common mistake.

**Vexil's value prop is surgical intervention in this specific moment.** By applying Shannon entropy and zero-egress structural validation, Vexil catches the mistake before it reaches the central repository, without bothering the developer with hundreds of false positives on `your_password_here` placeholders.

## The Adversary Action Vector

Contrast this with a true Supply Chain compromise (e.g., SolarWinds, 3CX, Volt Typhoon). In these scenarios:
1. The adversary may have already compromised the build system.
2. Secrets may be injected via a malicious dependency that is never committed to the primary repo.
3. Telemetry and network behavior are the only indicators of compromise.

A static secret scanner cannot—and should not—claim to detect these behaviors. If an adversary is already operating inside your pipeline, a tool that scans `.go` files for regex matches is functionally irrelevant.

## Honesty as a Security Feature

Vexil is an "Honest Tool." It does not claim to be a comprehensive Threat Intelligence platform. It does not map adversary campaigns or identify C2 traffic.

Instead, Vexil focuses on **Specialized Precision for Regulated Environments**. It solves a very real, very specific problem: How do you prevent accidental secret leaks in an environment (like OT/ICS or classified networks) where you cannot call a SaaS API to verify the finding?

## Conclusion

A scanner that catches developer mistakes before they become operational incidents is a useful tool. Calling it a supply chain security solution conflates the threat model and sets expectations that the control cannot meet. 

By being precise about what we are defending against—accidental exposure—we make Vexil more useful to the engineers and compliance officers who actually use it.
