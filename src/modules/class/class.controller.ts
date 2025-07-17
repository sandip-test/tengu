import { Body, Controller, Get, Post } from '@nestjs/common';
import { ClassService } from './class.service';
import { CreateClassDto } from './dto/class.dto';

@Controller('class')
export class ClassController {
  constructor(private readonly classService: ClassService) {}
  @Post('/create')
  async createClass(@Body() createClassDTO: CreateClassDto) {
    return this.classService.createClass(createClassDTO);
  }
  @Get('/all')
  async getAllClasses() {
    return this.classService.getAllClasses();
  }
}
