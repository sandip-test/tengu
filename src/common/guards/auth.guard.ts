import { verifyToken } from '@/lib/auth.lib';
import type { AuthUser } from '@/globals';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

@Injectable()
export class RequireAuth implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const authorizationHeader = request.headers.authorization;
    if (!authorizationHeader) {
      throw new UnauthorizedException('Authorization token is missing!');
    }

    const token: string = authorizationHeader.split(' ')[1];
    const data = verifyToken(token);
    console.log('Decoded JWT data:', data);
    if (!data) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // Set the user in the request object
    request.user = {
      id: data.id,
      email: data.email,
    } as AuthUser;
    return true;
  }
}

