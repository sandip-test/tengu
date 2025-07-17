import { Body, Controller, Post } from '@nestjs/common';
import { AcademicYearService } from './academic-year.service';
import { CreateAcademicYearDto } from './dto/academic-year.dto';

@Controller('academic-year')
export class AcademicYearController {
  constructor(private readonly academicYearService: AcademicYearService) {}
  @Post('/create')
  async createAcademicYear(@Body() data: CreateAcademicYearDto) {
    return this.academicYearService.createAcademicYear(data);
  }
}
