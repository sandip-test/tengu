import { Injectable } from '@nestjs/common';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { db } from '@/db';
import { users } from '../entities';
import { eq } from 'drizzle-orm';
import { passwordHash } from '@/lib/auth.lib';
import { SafeUserAPIResponse } from '@/common/dto/response/user-safe-api.response';

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
}
