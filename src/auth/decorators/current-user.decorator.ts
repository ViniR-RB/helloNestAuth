import { createParamDecorator } from '@nestjs/common';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host';
import { User } from '@prisma/client';
import { AuthRequest } from '../models/auth_request';

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContextHost): User => {
    const request = context.switchToHttp().getRequest<AuthRequest>();

    return request.user;
  },
);
