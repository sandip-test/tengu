import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './modules/users/users.module';
import { ClassModule } from './modules/class/class.module';
import { AcademicYearModule } from './modules/academic-year/academic-year.module';
import { AttendanceModule } from './modules/attendance/attendance.module';

@Module({
  imports: [UsersModule, ClassModule, AcademicYearModule, AttendanceModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
