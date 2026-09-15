import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { Role, RequirementStatus, DeliverableStatus, BugPriority, BugSeverity, BugStatus, MilestoneStatus } from '@prisma/client';
import { app } from '../src/app';
import { prisma } from '../src/lib/prisma';
import { config } from '../src/config';

vi.mock('../src/lib/prisma', () => ({
  prisma: {
    project: {
      findUnique: vi.fn(),
      update: vi.fn(),
      create: vi.fn(),
      findMany: vi.fn(),
      count: vi.fn(),
    },
    user: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
    },
    team: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    teamMember: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    requirement: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      count: vi.fn(),
    },
    userStory: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      findFirst: vi.fn(),
      create: vi.fn(),
    },
    task: {
      findUnique: vi.fn(),
      create: vi.fn(),
      delete: vi.fn(),
    },
    milestone: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    deliverable: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      count: vi.fn(),
    },
    bug: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
    activityLog: {
      create: vi.fn(),
      findMany: vi.fn(),
    },
    notification: {
      count: vi.fn(),
    },
  },
}));

describe('Role-Based Access Control (RBAC) Verification', () => {
  const generateToken = (payload: { id: string; email: string; role: Role }) => {
    return jwt.sign(payload, config.jwtSecret, { expiresIn: '1h' });
  };

  const facultyUser = {
    id: 'faculty-uuid-1',
    email: 'faculty@example.com',
    role: Role.FACULTY,
  };

  const teamLeadUser = {
    id: 'lead-uuid-1',
    email: 'lead@example.com',
    role: Role.TEAM_LEAD,
  };

  const teamMemberUser = {
    id: 'member-uuid-1',
    email: 'member@example.com',
    role: Role.TEAM_MEMBER,
  };

  const outsiderUser = {
    id: 'outsider-uuid-1',
    email: 'outsider@example.com',
    role: Role.TEAM_MEMBER,
  };

  const facultyToken = generateToken(facultyUser);
  const teamLeadToken = generateToken(teamLeadUser);
  const teamMemberToken = generateToken(teamMemberUser);
  const outsiderToken = generateToken(outsiderUser);

  const mockProjectWithTeam = {
    id: 'proj-uuid-1',
    name: 'Capstone Project',
    facultyId: 'faculty-uuid-1',
    teamId: 'team-uuid-1',
    team: {
      id: 'team-uuid-1',
      name: 'Alpha Team',
      leadId: 'lead-uuid-1',
      members: [
        { userId: 'lead-uuid-1', role: Role.TEAM_LEAD },
        { userId: 'member-uuid-1', role: Role.TEAM_MEMBER },
      ],
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Faculty-Only Actions', () => {
    describe('Faculty Dashboard (GET /api/faculty/dashboard)', () => {
      it('allows FACULTY to access dashboard', async () => {
        (prisma.user.findUnique as any).mockResolvedValue({
          id: facultyUser.id,
          name: 'Prof Faculty',
          email: facultyUser.email,
          role: Role.FACULTY,
        });

        (prisma.project.findMany as any).mockResolvedValue([]);
        (prisma.activityLog.findMany as any).mockResolvedValue([]);
        (prisma.notification.count as any).mockResolvedValue(0);

        const res = await request(app)
          .get('/api/faculty/dashboard')
          .set('Authorization', `Bearer ${facultyToken}`);

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_LEAD from accessing faculty dashboard with 403', async () => {
        const res = await request(app)
          .get('/api/faculty/dashboard')
          .set('Authorization', `Bearer ${teamLeadToken}`);

        expect(res.status).toBe(403);
      });

      it('denies TEAM_MEMBER from accessing faculty dashboard with 403', async () => {
        const res = await request(app)
          .get('/api/faculty/dashboard')
          .set('Authorization', `Bearer ${teamMemberToken}`);

        expect(res.status).toBe(403);
      });

      it('denies unauthenticated request to faculty dashboard with 401', async () => {
        const res = await request(app).get('/api/faculty/dashboard');

        expect(res.status).toBe(401);
      });
    });

    describe('Requirement Review & Approval (POST /api/requirements/:id/review)', () => {
      const mockRequirement = {
        id: 'req-uuid-1',
        title: 'User Authentication SRS',
        description: 'Secure login via JWT',
        status: RequirementStatus.IN_REVIEW,
        version: 1,
        projectId: 'proj-uuid-1',
        project: mockProjectWithTeam,
      };

      it('allows FACULTY to review and approve requirement', async () => {
        (prisma.requirement.findUnique as any).mockResolvedValue(mockRequirement);
        (prisma.requirement.update as any).mockResolvedValue({
          ...mockRequirement,
          status: RequirementStatus.APPROVED,
          version: 2,
        });

        const res = await request(app)
          .post('/api/requirements/req-uuid-1/review')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ action: 'APPROVE', feedback: 'Approved by faculty advisor' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_LEAD from reviewing requirement with 403', async () => {
        (prisma.requirement.findUnique as any).mockResolvedValue(mockRequirement);

        const res = await request(app)
          .post('/api/requirements/req-uuid-1/review')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ action: 'APPROVE' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('only faculty can review requirements');
      });

      it('denies TEAM_MEMBER from reviewing requirement with 403', async () => {
        (prisma.requirement.findUnique as any).mockResolvedValue(mockRequirement);

        const res = await request(app)
          .post('/api/requirements/req-uuid-1/review')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ action: 'APPROVE' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('only faculty can review requirements');
      });
    });

    describe('Deliverable Review (POST /api/deliverables/:id/review)', () => {
      const mockDeliverable = {
        id: 'del-uuid-1',
        title: 'SRS Document v1',
        status: DeliverableStatus.SUBMITTED,
        projectId: 'proj-uuid-1',
        project: mockProjectWithTeam,
      };

      it('allows FACULTY to start review on submitted deliverable', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDeliverable);
        (prisma.deliverable.update as any).mockResolvedValue({
          ...mockDeliverable,
          status: DeliverableStatus.UNDER_REVIEW,
        });

        const res = await request(app)
          .post('/api/deliverables/del-uuid-1/review')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ action: 'START_REVIEW' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_LEAD from reviewing deliverable with 403', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDeliverable);

        const res = await request(app)
          .post('/api/deliverables/del-uuid-1/review')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ action: 'START_REVIEW' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('FACULTY');
      });

      it('denies TEAM_MEMBER from reviewing deliverable with 403', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDeliverable);

        const res = await request(app)
          .post('/api/deliverables/del-uuid-1/review')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ action: 'START_REVIEW' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('FACULTY');
      });
    });
  });

  describe('Leadership Actions (FACULTY & TEAM_LEAD allowed, TEAM_MEMBER denied)', () => {
    describe('Update Project Details (PUT /api/projects/:id)', () => {
      it('allows FACULTY to update project details', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.project.update as any).mockResolvedValue({
          ...mockProjectWithTeam,
          name: 'Updated Project Name by Faculty',
        });

        const res = await request(app)
          .put('/api/projects/proj-uuid-1')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ name: 'Updated Project Name by Faculty' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to update project details', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.project.update as any).mockResolvedValue({
          ...mockProjectWithTeam,
          name: 'Updated Project Name by Lead',
        });

        const res = await request(app)
          .put('/api/projects/proj-uuid-1')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ name: 'Updated Project Name by Lead' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_MEMBER from updating project details with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .put('/api/projects/proj-uuid-1')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ name: 'Member Attempt Update' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('insufficient permissions');
      });

      it('denies OUTSIDER from updating project details with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .put('/api/projects/proj-uuid-1')
          .set('Authorization', `Bearer ${outsiderToken}`)
          .send({ name: 'Outsider Attempt Update' });

        expect(res.status).toBe(403);
      });
    });

    describe('Team Member Management (POST/DELETE /api/projects/:id/members)', () => {
      const candidateUser = {
        id: 'candidate-uuid-1',
        name: 'New Candidate',
        email: 'candidate@example.com',
        role: Role.TEAM_MEMBER,
      };

      it('allows FACULTY to add a team member', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.user.findUnique as any).mockResolvedValue(candidateUser);
        (prisma.teamMember.findUnique as any).mockResolvedValue(null);
        (prisma.teamMember.create as any).mockResolvedValue({
          teamId: 'team-uuid-1',
          userId: candidateUser.id,
          role: Role.TEAM_MEMBER,
          user: candidateUser,
        });

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/members')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ userId: candidateUser.id, role: Role.TEAM_MEMBER });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to add a team member', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.user.findUnique as any).mockResolvedValue(candidateUser);
        (prisma.teamMember.findUnique as any).mockResolvedValue(null);
        (prisma.teamMember.create as any).mockResolvedValue({
          teamId: 'team-uuid-1',
          userId: candidateUser.id,
          role: Role.TEAM_MEMBER,
          user: candidateUser,
        });

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/members')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ userId: candidateUser.id, role: Role.TEAM_MEMBER });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_MEMBER from adding team members with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/members')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ userId: candidateUser.id });

        expect(res.status).toBe(403);
      });

      it('denies TEAM_MEMBER from removing other team members with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .delete('/api/projects/proj-uuid-1/members/lead-uuid-1')
          .set('Authorization', `Bearer ${teamMemberToken}`);

        expect(res.status).toBe(403);
      });
    });

    describe('Deliverable Submission for Review (POST /api/deliverables/:id/submit)', () => {
      const mockDraftDeliverable = {
        id: 'del-draft-1',
        title: 'System Architecture Document',
        status: DeliverableStatus.DRAFT,
        projectId: 'proj-uuid-1',
        project: mockProjectWithTeam,
      };

      it('allows FACULTY to submit deliverable for review', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDraftDeliverable);
        (prisma.deliverable.update as any).mockResolvedValue({
          ...mockDraftDeliverable,
          status: DeliverableStatus.SUBMITTED,
        });

        const res = await request(app)
          .post('/api/deliverables/del-draft-1/submit')
          .set('Authorization', `Bearer ${facultyToken}`);

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to submit deliverable for review', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDraftDeliverable);
        (prisma.deliverable.update as any).mockResolvedValue({
          ...mockDraftDeliverable,
          status: DeliverableStatus.SUBMITTED,
        });

        const res = await request(app)
          .post('/api/deliverables/del-draft-1/submit')
          .set('Authorization', `Bearer ${teamLeadToken}`);

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_MEMBER from submitting deliverable with 403', async () => {
        (prisma.deliverable.findUnique as any).mockResolvedValue(mockDraftDeliverable);

        const res = await request(app)
          .post('/api/deliverables/del-draft-1/submit')
          .set('Authorization', `Bearer ${teamMemberToken}`);

        expect(res.status).toBe(403);
      });
    });

    describe('Milestone Management (POST /api/projects/:id/milestones)', () => {
      it('allows FACULTY to create a milestone', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.milestone.create as any).mockResolvedValue({
          id: 'ms-new-1',
          title: 'Sprint 1 Review',
          status: MilestoneStatus.UPCOMING,
          projectId: 'proj-uuid-1',
        });

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/milestones')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ title: 'Sprint 1 Review' });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to create a milestone', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.milestone.create as any).mockResolvedValue({
          id: 'ms-new-2',
          title: 'Midterm Submission',
          status: MilestoneStatus.UPCOMING,
          projectId: 'proj-uuid-1',
        });

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/milestones')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ title: 'Midterm Submission' });

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_MEMBER from creating a milestone with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/milestones')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ title: 'Member Milestone' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('insufficient permissions');
      });
    });

    describe('Bug Assignment (PUT /api/bugs/:id)', () => {
      const mockBug = {
        id: 'bug-uuid-1',
        title: 'Unhandled error on login failure',
        status: BugStatus.OPEN,
        priority: BugPriority.HIGH,
        severity: BugSeverity.MAJOR,
        projectId: 'proj-uuid-1',
        reporterId: 'member-uuid-1',
        assigneeId: null,
        project: mockProjectWithTeam,
      };

      it('allows FACULTY to assign bug to team member', async () => {
        (prisma.bug.findUnique as any).mockResolvedValue(mockBug);
        (prisma.teamMember.findUnique as any).mockResolvedValue({
          teamId: 'team-uuid-1',
          userId: 'member-uuid-1',
          role: Role.TEAM_MEMBER,
        });
        (prisma.bug.update as any).mockResolvedValue({
          ...mockBug,
          assigneeId: 'member-uuid-1',
        });

        const res = await request(app)
          .put('/api/bugs/bug-uuid-1')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send({ assigneeId: 'member-uuid-1' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to assign bug to team member', async () => {
        (prisma.bug.findUnique as any).mockResolvedValue(mockBug);
        (prisma.teamMember.findUnique as any).mockResolvedValue({
          teamId: 'team-uuid-1',
          userId: 'member-uuid-1',
          role: Role.TEAM_MEMBER,
        });
        (prisma.bug.update as any).mockResolvedValue({
          ...mockBug,
          assigneeId: 'member-uuid-1',
        });

        const res = await request(app)
          .put('/api/bugs/bug-uuid-1')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send({ assigneeId: 'member-uuid-1' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      });

      it('denies TEAM_MEMBER from assigning bug to someone else with 403', async () => {
        (prisma.bug.findUnique as any).mockResolvedValue(mockBug);

        const res = await request(app)
          .put('/api/bugs/bug-uuid-1')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send({ assigneeId: 'lead-uuid-1' });

        expect(res.status).toBe(403);
        expect(res.body.error).toContain('assign bugs');
      });
    });
  });

  describe('Team Contributor Actions (FACULTY, TEAM_LEAD & TEAM_MEMBER allowed, OUTSIDER denied)', () => {
    describe('Create Requirement in Project (POST /api/projects/:projectId/requirements)', () => {
      const requirementPayload = {
        title: 'Functional Requirement: Export to PDF',
        description: 'Users must be able to export reports to PDF format',
      };

      const mockCreatedRequirement = {
        id: 'req-new-1',
        ...requirementPayload,
        status: RequirementStatus.DRAFT,
        version: 1,
        projectId: 'proj-uuid-1',
      };

      it('allows FACULTY to create requirement in project', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.requirement.create as any).mockResolvedValue(mockCreatedRequirement);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/requirements')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send(requirementPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to create requirement in project', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.requirement.create as any).mockResolvedValue(mockCreatedRequirement);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/requirements')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send(requirementPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_MEMBER to create requirement in project', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.requirement.create as any).mockResolvedValue(mockCreatedRequirement);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/requirements')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send(requirementPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('denies OUTSIDER from creating requirement in project with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/requirements')
          .set('Authorization', `Bearer ${outsiderToken}`)
          .send(requirementPayload);

        expect(res.status).toBe(403);
      });
    });

    describe('Add User Story to Backlog (POST /api/backlog/:projectId/stories)', () => {
      const storyPayload = {
        title: 'As a user, I want to download reports',
        description: 'Story details',
        storyPoints: 3,
      };

      const mockCreatedStory = {
        id: 'story-new-1',
        ...storyPayload,
        projectId: 'proj-uuid-1',
        order: 1,
      };

      it('allows FACULTY to add story to project backlog', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.userStory.findFirst as any).mockResolvedValue(null);
        (prisma.userStory.create as any).mockResolvedValue(mockCreatedStory);

        const res = await request(app)
          .post('/api/backlog/proj-uuid-1/stories')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send(storyPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to add story to project backlog', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.userStory.findFirst as any).mockResolvedValue(null);
        (prisma.userStory.create as any).mockResolvedValue(mockCreatedStory);

        const res = await request(app)
          .post('/api/backlog/proj-uuid-1/stories')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send(storyPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_MEMBER to add story to project backlog', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.userStory.findFirst as any).mockResolvedValue(null);
        (prisma.userStory.create as any).mockResolvedValue(mockCreatedStory);

        const res = await request(app)
          .post('/api/backlog/proj-uuid-1/stories')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send(storyPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('denies OUTSIDER from adding story to project backlog with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .post('/api/backlog/proj-uuid-1/stories')
          .set('Authorization', `Bearer ${outsiderToken}`)
          .send(storyPayload);

        expect(res.status).toBe(403);
      });
    });

    describe('Report Bug in Project (POST /api/projects/:projectId/bugs)', () => {
      const bugPayload = {
        title: 'Broken navigation link on dashboard',
        severity: BugSeverity.MINOR,
        priority: BugPriority.LOW,
      };

      const mockCreatedBug = {
        id: 'bug-new-1',
        ...bugPayload,
        status: BugStatus.OPEN,
        projectId: 'proj-uuid-1',
        reporterId: 'member-uuid-1',
      };

      it('allows FACULTY to report a bug', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.bug.create as any).mockResolvedValue(mockCreatedBug);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/bugs')
          .set('Authorization', `Bearer ${facultyToken}`)
          .send(bugPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_LEAD to report a bug', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.bug.create as any).mockResolvedValue(mockCreatedBug);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/bugs')
          .set('Authorization', `Bearer ${teamLeadToken}`)
          .send(bugPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('allows TEAM_MEMBER to report a bug', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);
        (prisma.bug.create as any).mockResolvedValue(mockCreatedBug);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/bugs')
          .set('Authorization', `Bearer ${teamMemberToken}`)
          .send(bugPayload);

        expect(res.status).toBe(201);
        expect(res.body.success).toBe(true);
      });

      it('denies OUTSIDER from reporting a bug with 403', async () => {
        (prisma.project.findUnique as any).mockResolvedValue(mockProjectWithTeam);

        const res = await request(app)
          .post('/api/projects/proj-uuid-1/bugs')
          .set('Authorization', `Bearer ${outsiderToken}`)
          .send(bugPayload);

        expect(res.status).toBe(403);
      });
    });
  });
});
