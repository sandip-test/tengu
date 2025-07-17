import { Injectable } from '@nestjs/common';
import { db } from '@/db';
import { ApiResponse } from '@/common/dto/response/api-response';
import { CreateAcademicYearDto } from './dto/academic-year.dto';
import { academicYears } from '../entities';
@Injectable()
export class AcademicYearService {
  async createAcademicYear(data: CreateAcademicYearDto) {
    const newAcademicYear = await db
      .insert(academicYears)
      .values(data)
      .returning();
    return new ApiResponse(newAcademicYear[0]);
  }
}
