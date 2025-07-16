import { Injectable } from '@nestjs/common';
import { CreateClassDto } from './dto/class.dto';
import { classes } from '../entities';
import { db } from '@/db';
import { ApiResponse } from '@/common/dto/response/api-response';
@Injectable()
export class ClassService {
  async createClass(data: CreateClassDto) {
    const newClass = await db.insert(classes).values(data).returning();
    return new ApiResponse(newClass[0]);
  }
}
