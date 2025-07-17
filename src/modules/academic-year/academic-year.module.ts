import { Module } from '@nestjs/common';
import { AcademicYearService } from './academic-year.service';
import { AcademicYearController } from './academic-year.controller';

@Module({
  providers: [AcademicYearService],
  controllers: [AcademicYearController],
})
export class AcademicYearModule {}
