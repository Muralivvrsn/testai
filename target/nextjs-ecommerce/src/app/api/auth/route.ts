import { NextRequest, NextResponse } from 'next/server';

// Simulated user database
interface User {
  id: string;
  email: string;
  password: string; // In real app, this would be hashed
  name: string;
  createdAt: Date;
}

const users: User[] = [
  {
    id: '1',
    email: 'demo@example.com',
    password: 'password123',
    name: 'Demo User',
    createdAt: new Date('2024-01-01')
  }
];

// Simulated sessions
const sessions = new Map<string, string>(); // token -> userId

function generateToken(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

export async function POST(request: NextRequest) {
  await new Promise(resolve => setTimeout(resolve, 500)); // Simulate network delay

  const body = await request.json();
  const { action } = body;

  switch (action) {
    case 'login': {
      const { email, password } = body;

      if (!email || !password) {
        return NextResponse.json(
          { error: 'Email and password are required' },
          { status: 400 }
        );
      }

      const user = users.find(u => u.email === email);

      if (!user || user.password !== password) {
        return NextResponse.json(
          { error: 'Invalid email or password' },
          { status: 401 }
        );
      }

      const token = generateToken();
      sessions.set(token, user.id);

      return NextResponse.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        token,
      });
    }

    case 'register': {
      const { email, password, name } = body;

      if (!email || !password || !name) {
        return NextResponse.json(
          { error: 'Name, email, and password are required' },
          { status: 400 }
        );
      }

      // Validate email format
      if (!/\S+@\S+\.\S+/.test(email)) {
        return NextResponse.json(
          { error: 'Invalid email format' },
          { status: 400 }
        );
      }

      // Check password length
      if (password.length < 6) {
        return NextResponse.json(
          { error: 'Password must be at least 6 characters' },
          { status: 400 }
        );
      }

      // Check if email already exists
      if (users.find(u => u.email === email)) {
        return NextResponse.json(
          { error: 'Email already registered' },
          { status: 409 }
        );
      }

      const newUser: User = {
        id: (users.length + 1).toString(),
        email,
        password,
        name,
        createdAt: new Date(),
      };

      users.push(newUser);

      const token = generateToken();
      sessions.set(token, newUser.id);

      return NextResponse.json({
        success: true,
        user: {
          id: newUser.id,
          email: newUser.email,
          name: newUser.name,
        },
        token,
      }, { status: 201 });
    }

    case 'logout': {
      const token = request.headers.get('authorization')?.replace('Bearer ', '');

      if (token) {
        sessions.delete(token);
      }

      return NextResponse.json({ success: true });
    }

    case 'verify': {
      const token = request.headers.get('authorization')?.replace('Bearer ', '');

      if (!token) {
        return NextResponse.json(
          { error: 'No token provided' },
          { status: 401 }
        );
      }

      const userId = sessions.get(token);

      if (!userId) {
        return NextResponse.json(
          { error: 'Invalid or expired token' },
          { status: 401 }
        );
      }

      const user = users.find(u => u.id === userId);

      if (!user) {
        return NextResponse.json(
          { error: 'User not found' },
          { status: 404 }
        );
      }

      return NextResponse.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      });
    }

    case 'forgot-password': {
      const { email } = body;

      if (!email) {
        return NextResponse.json(
          { error: 'Email is required' },
          { status: 400 }
        );
      }

      const user = users.find(u => u.email === email);

      // Always return success to prevent email enumeration
      return NextResponse.json({
        success: true,
        message: 'If an account exists with this email, you will receive a password reset link.',
      });
    }

    case 'reset-password': {
      const { token, newPassword } = body;

      if (!token || !newPassword) {
        return NextResponse.json(
          { error: 'Token and new password are required' },
          { status: 400 }
        );
      }

      if (newPassword.length < 6) {
        return NextResponse.json(
          { error: 'Password must be at least 6 characters' },
          { status: 400 }
        );
      }

      // In real app, validate reset token and update password
      return NextResponse.json({
        success: true,
        message: 'Password has been reset successfully.',
      });
    }

    case 'social-login': {
      const { provider, accessToken } = body;

      if (!provider || !accessToken) {
        return NextResponse.json(
          { error: 'Provider and access token are required' },
          { status: 400 }
        );
      }

      // Simulate social login verification
      const socialUser = {
        id: `social-${Date.now()}`,
        email: `user@${provider.toLowerCase()}.com`,
        name: `${provider} User`,
      };

      const token = generateToken();
      sessions.set(token, socialUser.id);

      return NextResponse.json({
        success: true,
        user: socialUser,
        token,
      });
    }

    default:
      return NextResponse.json(
        { error: 'Invalid action' },
        { status: 400 }
      );
  }
}

export async function GET(request: NextRequest) {
  const token = request.headers.get('authorization')?.replace('Bearer ', '');

  if (!token) {
    return NextResponse.json(
      { authenticated: false },
      { status: 401 }
    );
  }

  const userId = sessions.get(token);

  if (!userId) {
    return NextResponse.json(
      { authenticated: false },
      { status: 401 }
    );
  }

  const user = users.find(u => u.id === userId);

  if (!user) {
    return NextResponse.json(
      { authenticated: false },
      { status: 401 }
    );
  }

  return NextResponse.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
  });
}
