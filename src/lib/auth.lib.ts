import { USERS } from '@/db/schema';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

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
export const verifyToken = (token: string): Promise<JwtPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      process.env.JWT_SECRET!,
      (err: Error | null, decoded: any) => {
        if (err) {
          return reject(err);
        }
        resolve(decoded as JwtPayload);
      },
    );
  });
};
