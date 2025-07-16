import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './modules/users/users.module';
import { ClassModule } from './modules/class/class.module';

@Module({
  imports: [UsersModule, ClassModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
