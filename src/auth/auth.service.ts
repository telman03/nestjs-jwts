import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthSignInDto, AuthSignUpDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { UserRole } from '@prisma/client';

@Injectable()
export class AuthService {

    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService
    ) {}

    async signupLocal(dto: AuthSignUpDto): Promise<Tokens> {
        const { firstname, lastname, email, password, role } = dto;

        const hash = await this.hashData(password);

        const newUser = await this.prisma.user.create({
            data: {
                email,
                firstname,
                lastname,
                hash,
                role,
            },
        });

        const tokens = await this.getTokens(newUser.id, newUser.email, newUser.firstname, newUser.lastname, newUser.role);
        await this.updateRtHash(newUser.id, tokens.refreshToken);
        return tokens;
    }

    async signinLocal(dto: AuthSignInDto): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (!user) throw new ForbiddenException('Access denied');

        const passwordMatches = await bcrypt.compare(dto.password, user.hash);

        if (!passwordMatches) throw new ForbiddenException('Access denied');

        const tokens = await this.getTokens(user.id, user.email, user.firstname, user.lastname, user.role);
        await this.updateRtHash(user.id, tokens.refreshToken);
        return tokens;
    }

    async getUserData(userId: number) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user) {
            throw new Error('User not found');
        }

        // You can customize the returned user data here if needed
        const { hash, hashRt, ...userData } = user;

        return userData;
    }

    async logout(userId: number) {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashRt: {
                    not: null,
                },
            },
            data: {
                hashRt: null,
            },
        });
    }

    async refreshTokens(userId: number, rt: string) {
        const user = await this.prisma.user.findUnique({
            where: {
                id: userId,
            },
        });
        if (!user || !user.hashRt) throw new ForbiddenException('Access Denied');

        const rtMatches = await bcrypt.compare(user.hashRt, rt);
        if (!rtMatches) throw new ForbiddenException('Access Denied');

        const tokens = await this.getTokens(user.id, user.email, user.firstname, user.lastname, user.role);
        await this.updateRtHash(user.id, tokens.refreshToken);

        return tokens;
    }

    async updateRtHash(userId: number, rt: string) {
        const hash = await this.hashData(rt);

        await this.prisma.user.update({
            where: {
                id: userId,
            },
            data: {
                hashRt: hash,
            },
        });
    }

    hashData(data: string) {
        return bcrypt.hash(data, 10);
    }

    async getTokens(userId: number, email: string, firstname: string, lastname: string, role: UserRole): Promise<Tokens> {
        const [at, rt] = await Promise.all([
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email,
                    firstname,
                    lastname,
                    role
                    
                },
                {
                    secret: 'at-secret',
                    expiresIn: 60 * 15,
                }
            ),
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email,
                },
                {
                    secret: 'rt-secret',
                    expiresIn: 60 * 60 * 24 * 7,
                }
            ),
        ]);
        return {
            accessToken: at,
            refreshToken: rt,
        };
    }
}
