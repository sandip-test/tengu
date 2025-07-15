import { Controller, Post, Body, Get } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto, LoginUserDto } from './dto/user.dto';
import { ProtectFromUnauthorized } from '@/common/decorators';
import { UserRoleEnum } from '../entities';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('/register')
  async registerUser(@Body() createUserDto: CreateUserDto) {
    return this.usersService.createUser(createUserDto);
  }
  @Post('/login')
  async loginUser(@Body() loginUserDto: LoginUserDto) {
    return this.usersService.loginUser(loginUserDto);
  }
  @ProtectFromUnauthorized(UserRoleEnum.STUDENT)
  @Get('/user')
  async allUsers() {
    return this.usersService.listAllUsers();
  }
}
