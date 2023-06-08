import { Injectable } from '@nestjs/common';
import * as brcypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}
  async create(createUserDto: CreateUserDto) {
    const data = {
      ...createUserDto,
      password: await brcypt.hash(createUserDto.password, 10),
    };

    const createdUser = await this.prisma.user.create({
      data,
    });
    return {
      ...createdUser,
      password: undefined,
    };
  }
  async findByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }
}
