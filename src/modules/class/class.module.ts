import { Module } from '@nestjs/common';
import { ClassService } from './class.service';

@Module({
  providers: [ClassService]
})
export class ClassModule {}
