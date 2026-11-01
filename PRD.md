# Product Requirements Document
## Agent Consent on Supabase (v0)

**Version:** 0.1  
**Status:** Exploratory prototype  
**Document type:** Retrospective PRD

## 1. Overview

Agent Consent on Supabase is a prototype exploring how users can grant AI agents controlled access to their data, understand the permissions they have granted, and revoke access when needed.

The central idea is that access should be enforced by the data layer—not left entirely to the AI model or application logic.

## 2. Problem Statement

AI agents increasingly need access to personal data to complete tasks on a user's behalf. Giving an agent broad access to an entire dataset can expose information that is irrelevant to the task and create avoidable privacy risks.

**How might we let users grant AI agents only the access they need, while keeping those permissions visible and revocable?**

## 3. Target Users

| Persona | Need |
|---|---|
| App developer | A way to integrate agents without exposing all user data. |
| End user | Clear control over what an agent can access, with the ability to revoke permission. |
| Security reviewer | Confidence that access rules are enforced and access decisions can be reviewed. |

## 4. Proposed Solution

A consent layer built with Supabase that allows users to grant an AI agent scoped access to their data.

The v0 prototype explores four core capabilities:

- **Scoped consent:** An OAuth-style consent screen through which users grant specific permissions.
- **Access enforcement:** Supabase Row Level Security (RLS) restricts which records the agent can retrieve based on the user's grant.
- **Permission revocation:** Users can withdraw access; subsequent requests should be denied access to protected records.
- **Auditability:** Grant events (approved, revoked, last used) are recorded to support visibility into access decisions; a per-request audit log is proposed for future development.

## 5. Functional Requirements

1. Users can review and approve an agent's requested permissions.
2. Granted permissions are associated with the relevant user and agent.
3. Database access is restricted according to the approved permission scope.
4. Revoking a grant prevents subsequent requests from retrieving records protected by that grant.
5. Grant events (approved, revoked, last used) are recorded; a per-request audit log is proposed for future development.

## 6. Prototype Validation

The prototype's access behaviour was tested against a Supabase database using `agent:peek` and `agent:view`. These commands use the agent's access key to inspect what the agent is permitted to retrieve without invoking an AI model.

The Claude-powered `agent:ask` command has been implemented but has **not** been live-tested because it requires a paid Anthropic API key.

### Key observation

During testing, restricting access to health-related notes did not prevent a related health task from remaining accessible.

This highlighted a potential gap in category-based permissions: restricting one type of record may not prevent sensitive information from appearing in related content.

It raises an important product question: are permissions being designed around how developers organise data, or around how users understand privacy in context?

## 7. Success Measures

If the prototype is developed further, potential measures include:

- Time required for a developer to complete their first agent integration.
- Percentage of access grants configured with least-privilege scopes.
- Successful enforcement of permission changes and revocations.
- Reduction in unauthorised data retrieval across permission tests.

## 8. Out of Scope for v0

- Production-ready deployment.
- Live Claude response generation and validation.
- Comprehensive protection against sensitive information surfacing through related records.
- A complete, production-grade audit and compliance system.

## 9. Open Product Question

**Are we designing privacy around how developers organise data, or around how users actually understand privacy?**

This is an important question to explore as AI agents become more autonomous.

---

## Implementation Note

This document describes the prototype retrospectively. It distinguishes implemented and tested behaviour from capabilities that remain untested or are proposed for future development. It is not a production security or compliance specification.
