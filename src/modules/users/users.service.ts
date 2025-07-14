import { Injectable } from '@nestjs/common';
import { CreateUserDto, LoginUserDto, UpdateUserDto } from './dto/user.dto';
import { db } from '@/db';
import { users } from '../entities';
import { eq } from 'drizzle-orm';
import { generateToken, passwordCompare, passwordHash } from '@/lib/auth.lib';
import { SafeUserAPIResponse } from '@/common/dto/response/user-safe-api.response';
import { ApiResponse } from '@/common/dto/response/api-response';

@Injectable()
export class UsersService {
  async createUser(userData: CreateUserDto) {
    const hashedPassword = await passwordHash(userData.password);
    const newUser = await db
      .insert(users)
      .values({ ...userData, password: hashedPassword })
      .returning();

    return SafeUserAPIResponse(newUser[0]);
  }
  async findUserByEmail(email: string) {
    const user = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    return SafeUserAPIResponse(user[0]);
  }
  async findUserById(id: string) {
    const user = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return SafeUserAPIResponse(user[0]);
  }
  async updateUser(id: string, userData: UpdateUserDto) {
    const updatedUser = await db
      .update(users)
      .set(userData)
      .where(eq(users.id, id))
      .returning();
    return SafeUserAPIResponse(updatedUser[0]);
  }
  async loginUser(user: LoginUserDto) {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, user.email))
      .limit(1);
    if (!existingUser) {
      return new ApiResponse({
        status: 'error',
        message: 'User with this email does not exist',
      });
    }
    const isPasswordValid = await passwordCompare(
      user.password,
      existingUser[0].password,
    );
    if (!isPasswordValid) {
      return new ApiResponse({
        status: 'error',
        message: 'Invalid password',
      });
    }
    const token = generateToken(existingUser[0]);
    return new ApiResponse({
      status: 'success',
      message: 'User logged in successfully',
      data: {
        user: SafeUserAPIResponse(existingUser[0]),
        token,
      },
    });
  }
}
