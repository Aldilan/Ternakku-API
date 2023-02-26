import { CreateAuthDto } from './dto/create-auth.dto';
import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constant';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: CreateAuthDto) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (foundUser) {
      throw new BadRequestException('Email already exists');
    }
    const hashedPassword = await this.hashPassword(password);
    await this.prisma.user.create({
      data: {
        email: email,
        password: hashedPassword,
      },
    });
    return { message: 'SignUp Successfull!' };
  }

  async login(dto: CreateAuthDto) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (!foundUser) {
      throw new BadRequestException('Something wrong, try again later');
    }
    const hashedPassword = await this.hashPassword(password);
    const isMatch = await this.comparePassword({
      password,
      hashedpassword: foundUser.password,
    });

    if (!isMatch) {
      throw new BadRequestException('Something wrong, try again later');
    }

    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    return { token };
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePassword(args: { password: string; hashedpassword: string }) {
    return await bcrypt.compare(args.password, args.hashedpassword);
  }

  async signToken(args: { id: string; email: string }) {
    const playload = args;

    return this.jwt.signAsync(playload, { secret: jwtSecret });
  }
}
