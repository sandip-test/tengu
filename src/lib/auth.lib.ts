import { USERS } from '@/db/schema';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { UnauthorizedException } from '@nestjs/common';

export const passwordHash = async (password: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

export const passwordCompare = async (
  password: string,
  hash: string,
): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

// Define the JWT payload interface
export interface JwtPayload {
  id: string;
  email: string;
}

// Token generation using defined payload type
export const generateToken = (user: Pick<USERS, 'id' | 'email'>): string => {
  const payload: JwtPayload = {
    id: user.id,
    email: user.email,
  };

  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: '24h',
  });
};

// Safe token verification returning typed payload
export const verifyToken = (token: string): JwtPayload => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    return decoded;
  } catch (err) {
    console.error('Token verification error:', err);
    throw new UnauthorizedException('Invalid or expired token!');
  }
};
