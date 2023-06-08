import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UserService } from 'src/user/user.service';
import { UnauthorizedError } from './erros/unauthorized.error';
import { UserPayload } from './models/user_payload';
import { UserToken } from './models/user_token';
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User): Promise<UserToken> {
    const payload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };
    const jwtToken = this.jwtService.sign(payload);

    return {
      access_token: jwtToken,
    };
  }
  async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    console.log(user);
    if (user) {
      const isPasswordIsValid = await bcrypt.compare(password, user.password);
      console.log(isPasswordIsValid);
      if (isPasswordIsValid) {
        return {
          ...user,
          password: undefined,
        };
      }
    }
    throw new UnauthorizedError(
      'Email address or password provided is incorret.',
    );
  }
}
