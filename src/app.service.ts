import { Injectable } from '@nestjs/common';
import { APP_CONFIG } from './config';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
  returnAPIDetails() {
    return {
      name: APP_CONFIG.NAME,
      version: APP_CONFIG.CURRENT_VERSION,
      docs:
        process.env.ENABLE_SWAGGER === 'true' ? '/docs' : 'No Documentation',
      environment: process.env.NODE_ENV || 'development',
    };
  }
}
