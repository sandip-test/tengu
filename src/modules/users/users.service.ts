import { Injectable } from '@nestjs/common';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { db } from '@/db';
import { users } from '../entities';
import { eq } from 'drizzle-orm';
import { ApiResponse } from '@/common/dto/response/api-response';

@Injectable()
export class UsersService {
  async createUser(userData: CreateUserDto) {
    const newUser = await db.insert(users).values(userData).returning();
    return new ApiResponse(newUser[0]);
  }
  async findUserByEmail(email: string) {
    const user = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    return new ApiResponse(user);
  }
  async findUserById(id: string) {
    const user = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return new ApiResponse(user);
  }
  async updateUser(id: string, userData: UpdateUserDto) {
    const updatedUser = await db
      .update(users)
      .set(userData)
      .where(eq(users.id, id));
    return new ApiResponse(updatedUser);
  }
}
