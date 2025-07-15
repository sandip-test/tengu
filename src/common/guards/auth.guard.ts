import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  mixin,
  Type,
  ForbiddenException,
} from '@nestjs/common';
import { verifyToken } from '@/lib/auth.lib';
import { UserRoleEnum } from '@/db/schema';

export function RequireAuth(allowedRoles?: UserRoleEnum[]): Type<CanActivate> {
  @Injectable()
  class RoleGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
      const request = context.switchToHttp().getRequest();
      const authHeader = request.headers.authorization;

      if (!authHeader) {
        throw new UnauthorizedException('Authorization token is missing');
      }

      const token: string = authHeader.split(' ')[1];
      const data = verifyToken(token);

      if (!data) {
        throw new UnauthorizedException('Invalid or expired token');
      }

      request.user = {
        id: data.id,
        email: data.email,
        role: data.role,
      };

      if (
        allowedRoles &&
        allowedRoles.length > 0 &&
        !allowedRoles.includes(data.role)
      ) {
        throw new ForbiddenException(`Access denied for role: ${data.role}`);
      }

      return true;
    }
  }

  return mixin(RoleGuard);
}
