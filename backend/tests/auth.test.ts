import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import express, { Request, Response } from 'express';
import { Role } from '@prisma/client';
import { app } from '../src/app';
import { prisma } from '../src/lib/prisma';
import { config } from '../src/config';
import { authenticate, requireRole } from '../src/middleware/auth';

vi.mock('../src/lib/prisma', () => ({
  prisma: {
    user: {
      findUnique: vi.fn(),
      create: vi.fn(),
    },
  },
}));

describe('Authentication & Authorization Suite', () => {
  const setupProtectedApp = () => {
    const testApp = express();
    testApp.use(express.json());

    testApp.get('/test/protected', authenticate, (req: Request, res: Response) => {
      res.status(200).json({
        success: true,
        user: req.user,
      });
    });

    testApp.get(
      '/test/faculty-only',
      authenticate,
      requireRole([Role.FACULTY]),
      (req: Request, res: Response) => {
        res.status(200).json({
          success: true,
          message: 'Faculty route access granted',
        });
      }
    );

    testApp.get(
      '/test/lead-or-faculty',
      authenticate,
      requireRole([Role.TEAM_LEAD, Role.FACULTY]),
      (req: Request, res: Response) => {
        res.status(200).json({
          success: true,
          message: 'Leadership access granted',
        });
      }
    );

    return testApp;
  };

  const testApp = setupProtectedApp();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('User Registration (POST /api/auth/register)', () => {
    it('should register a new user successfully with default role', async () => {
      const mockCreatedUser = {
        id: 'user-uuid-1',
        email: 'john@example.com',
        name: 'John Doe',
        password: '$2a$10$hashedpasswordstringplaceholder',
        role: Role.TEAM_MEMBER,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(null);
      (prisma.user.create as any).mockResolvedValue(mockCreatedUser);

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: 'Password123!',
          name: 'John Doe',
        });

      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body.message).toBe('User registered successfully');
      expect(response.body.data).toHaveProperty('user');
      expect(response.body.data).toHaveProperty('token');

      const user = response.body.data.user;
      expect(user.id).toBe('user-uuid-1');
      expect(user.email).toBe('john@example.com');
      expect(user.name).toBe('John Doe');
      expect(user.role).toBe('TEAM_MEMBER');
      expect(user).not.toHaveProperty('password');

      const decoded = jwt.verify(response.body.data.token, config.jwtSecret) as any;
      expect(decoded.id).toBe('user-uuid-1');
      expect(decoded.email).toBe('john@example.com');
      expect(decoded.role).toBe('TEAM_MEMBER');

      expect(prisma.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          email: 'john@example.com',
          name: 'John Doe',
          role: 'TEAM_MEMBER',
        }),
      });
    });

    it('should register a user with custom FACULTY role if specified', async () => {
      const mockCreatedUser = {
        id: 'faculty-uuid-1',
        email: 'prof@example.com',
        name: 'Prof Smith',
        password: '$2a$10$hashedpasswordstringplaceholder',
        role: Role.FACULTY,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(null);
      (prisma.user.create as any).mockResolvedValue(mockCreatedUser);

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'prof@example.com',
          password: 'Password123!',
          name: 'Prof Smith',
          role: 'FACULTY',
        });

      expect(response.status).toBe(201);
      expect(response.body.data.user.role).toBe('FACULTY');
    });

    it('should normalize email to lowercase and trim spaces on registration', async () => {
      const mockCreatedUser = {
        id: 'user-uuid-2',
        email: 'normalized@example.com',
        name: 'Trimmed Name',
        password: '$2a$10$hashedpasswordstringplaceholder',
        role: Role.TEAM_MEMBER,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(null);
      (prisma.user.create as any).mockResolvedValue(mockCreatedUser);

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: '  NORMALIZED@Example.COM  ',
          password: 'Password123!',
          name: '  Trimmed Name  ',
        });

      expect(response.status).toBe(201);
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          email: 'normalized@example.com',
          name: 'Trimmed Name',
        }),
      });
    });

    it('should return 400 if email is missing', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          password: 'Password123!',
          name: 'John Doe',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Email is required');
    });

    it('should return 400 if email is empty or only whitespace', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: '   ',
          password: 'Password123!',
          name: 'John Doe',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Email is required');
    });

    it('should return 400 if email format is invalid', async () => {
      const invalidEmails = ['invalid-email', 'missingatsign.com', 'user@domain', 'user@.com', '@domain.com'];

      for (const email of invalidEmails) {
        const response = await request(app)
          .post('/api/auth/register')
          .send({
            email,
            password: 'Password123!',
            name: 'John Doe',
          });

        expect(response.status).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.message).toBe('Invalid email format');
      }
    });

    it('should return 400 if password is missing', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          name: 'John Doe',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Password is required');
    });

    it('should return 400 if password is shorter than 6 characters', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: '12345',
          name: 'John Doe',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Password must be at least 6 characters long');
    });

    it('should return 400 if name is missing', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: 'Password123!',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Name is required');
    });

    it('should return 400 if name is empty or only whitespace', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: 'Password123!',
          name: '   ',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Name is required');
    });

    it('should return 400 if role is invalid', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: 'Password123!',
          name: 'John Doe',
          role: 'INVALID_ROLE',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid role');
    });

    it('should return 400 if registering with disallowed role like TEAM_LEAD directly', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'lead@example.com',
          password: 'Password123!',
          name: 'Team Lead Candidate',
          role: 'TEAM_LEAD',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid role');
    });

    it('should return 409 if user email already exists', async () => {
      (prisma.user.findUnique as any).mockResolvedValue({
        id: 'existing-id',
        email: 'john@example.com',
      });

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'john@example.com',
          password: 'Password123!',
          name: 'John Doe',
        });

      expect(response.status).toBe(409);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('User with this email already exists');
      expect(prisma.user.create).not.toHaveBeenCalled();
    });
  });

  describe('User Login (POST /api/auth/login)', () => {
    it('should login successfully with valid credentials', async () => {
      const rawPassword = 'Password123!';
      const hashedPassword = await bcrypt.hash(rawPassword, 10);

      const mockUser = {
        id: 'user-uuid-1',
        email: 'john@example.com',
        name: 'John Doe',
        password: hashedPassword,
        role: Role.TEAM_MEMBER,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(mockUser);

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'john@example.com',
          password: rawPassword,
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Login successful');
      expect(response.body.data).toHaveProperty('user');
      expect(response.body.data).toHaveProperty('token');

      const user = response.body.data.user;
      expect(user.id).toBe('user-uuid-1');
      expect(user.email).toBe('john@example.com');
      expect(user).not.toHaveProperty('password');

      const decoded = jwt.verify(response.body.data.token, config.jwtSecret) as any;
      expect(decoded.id).toBe('user-uuid-1');
      expect(decoded.email).toBe('john@example.com');
      expect(decoded.role).toBe('TEAM_MEMBER');
    });

    it('should support email case insensitivity and whitespace trimming during login', async () => {
      const rawPassword = 'Password123!';
      const hashedPassword = await bcrypt.hash(rawPassword, 10);

      const mockUser = {
        id: 'user-uuid-1',
        email: 'john@example.com',
        name: 'John Doe',
        password: hashedPassword,
        role: Role.TEAM_MEMBER,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(mockUser);

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: '  JOHN@EXAMPLE.COM  ',
          password: rawPassword,
        });

      expect(response.status).toBe(200);
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { email: 'john@example.com' },
      });
    });

    it('should return 400 if email is missing', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          password: 'Password123!',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Email is required');
    });

    it('should return 400 if email is empty string or only whitespace', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: '   ',
          password: 'Password123!',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Email is required');
    });

    it('should return 400 if password is missing', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'john@example.com',
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Password is required');
    });

    it('should return 401 if user does not exist', async () => {
      (prisma.user.findUnique as any).mockResolvedValue(null);

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'Password123!',
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email or password');
    });

    it('should return 401 if password does not match', async () => {
      const hashedPassword = await bcrypt.hash('CorrectPassword123!', 10);

      const mockUser = {
        id: 'user-uuid-1',
        email: 'john@example.com',
        name: 'John Doe',
        password: hashedPassword,
        role: Role.TEAM_MEMBER,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (prisma.user.findUnique as any).mockResolvedValue(mockUser);

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'john@example.com',
          password: 'WrongPassword!',
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email or password');
    });
  });

  describe('Authentication Middleware (authenticate)', () => {
    it('should return 401 if Authorization header is missing', async () => {
      const response = await request(testApp).get('/test/protected');

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Authentication required' });
    });

    it('should return 401 if Authorization header does not use Bearer scheme', async () => {
      const invalidHeaders = [
        'Basic dXNlcjpwYXNz',
        'Token some-token-value',
        'Bearer',
        'bearer sometoken',
        'Custom sometoken',
      ];

      for (const header of invalidHeaders) {
        const response = await request(testApp)
          .get('/test/protected')
          .set('Authorization', header);

        expect(response.status).toBe(401);
        expect(response.body).toEqual({ error: 'Authentication required' });
      }
    });

    it('should return 401 if Bearer token is malformed', async () => {
      const response = await request(testApp)
        .get('/test/protected')
        .set('Authorization', 'Bearer invalid.malformed.jwttoken');

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });

    it('should return 401 if token is signed with a different secret', async () => {
      const invalidSecretToken = jwt.sign(
        { id: 'user-uuid-1', email: 'john@example.com', role: Role.TEAM_MEMBER },
        'completely-different-secret-key-12345',
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/test/protected')
        .set('Authorization', `Bearer ${invalidSecretToken}`);

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });

    it('should return 401 if token is expired', async () => {
      const expiredToken = jwt.sign(
        { id: 'user-uuid-1', email: 'john@example.com', role: Role.TEAM_MEMBER },
        config.jwtSecret,
        { expiresIn: '-10s' }
      );

      const response = await request(testApp)
        .get('/test/protected')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });

    it('should allow request and set req.user if token is valid', async () => {
      const validToken = jwt.sign(
        { id: 'user-uuid-10', email: 'valid@example.com', role: Role.TEAM_MEMBER },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/test/protected')
        .set('Authorization', `Bearer ${validToken}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.user).toMatchObject({
        id: 'user-uuid-10',
        email: 'valid@example.com',
        role: 'TEAM_MEMBER',
      });
    });
  });

  describe('Role Authorization Middleware (requireRole)', () => {
    it('should return 401 if req.user is undefined when requireRole is called', () => {
      const req: Partial<Request> = {};
      const res: Partial<Response> = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      const middleware = requireRole([Role.FACULTY]);
      middleware(req as Request, res as Response, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if authenticated user lacks the required role', async () => {
      const memberToken = jwt.sign(
        { id: 'member-1', email: 'member@example.com', role: Role.TEAM_MEMBER },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/test/faculty-only')
        .set('Authorization', `Bearer ${memberToken}`);

      expect(response.status).toBe(403);
      expect(response.body).toEqual({ error: 'Access denied: insufficient permissions' });
    });

    it('should allow access if user has the exact required role', async () => {
      const facultyToken = jwt.sign(
        { id: 'faculty-1', email: 'faculty@example.com', role: Role.FACULTY },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/test/faculty-only')
        .set('Authorization', `Bearer ${facultyToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        success: true,
        message: 'Faculty route access granted',
      });
    });

    it('should allow access if user has any one of multiple allowed roles', async () => {
      const leadToken = jwt.sign(
        { id: 'lead-1', email: 'lead@example.com', role: Role.TEAM_LEAD },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const facultyToken = jwt.sign(
        { id: 'faculty-1', email: 'faculty@example.com', role: Role.FACULTY },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const memberToken = jwt.sign(
        { id: 'member-1', email: 'member@example.com', role: Role.TEAM_MEMBER },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      const leadRes = await request(testApp)
        .get('/test/lead-or-faculty')
        .set('Authorization', `Bearer ${leadToken}`);
      expect(leadRes.status).toBe(200);
      expect(leadRes.body.success).toBe(true);

      const facultyRes = await request(testApp)
        .get('/test/lead-or-faculty')
        .set('Authorization', `Bearer ${facultyToken}`);
      expect(facultyRes.status).toBe(200);
      expect(facultyRes.body.success).toBe(true);

      const memberRes = await request(testApp)
        .get('/test/lead-or-faculty')
        .set('Authorization', `Bearer ${memberToken}`);
      expect(memberRes.status).toBe(403);
      expect(memberRes.body).toEqual({ error: 'Access denied: insufficient permissions' });
    });
  });

  describe('Authentication Failure Cases on Main Application Routes', () => {
    it('should reject unauthenticated request to /api/projects with 401', async () => {
      const response = await request(app).get('/api/projects');

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Authentication required' });
    });

    it('should reject request to /api/projects with expired token with 401', async () => {
      const expiredToken = jwt.sign(
        { id: 'user-uuid-1', email: 'user@example.com', role: Role.TEAM_MEMBER },
        config.jwtSecret,
        { expiresIn: '-1s' }
      );

      const response = await request(app)
        .get('/api/projects')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });

    it('should reject request to /api/projects with corrupted token with 401', async () => {
      const response = await request(app)
        .get('/api/projects')
        .set('Authorization', 'Bearer corrupted-token-segment');

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid or expired token' });
    });
  });
});
