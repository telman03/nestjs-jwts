import { IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { UserRole } from '@prisma/client';
import { ApiParam, ApiProperty } from '@nestjs/swagger';
export class AuthSignUpDto {

    @IsNotEmpty()
    @IsString()
    @ApiProperty()
    email: string;

    @IsNotEmpty()
    @IsString()
    @ApiProperty()
    firstname: string;

    @IsNotEmpty()
    @ApiProperty()
    @IsString()
    lastname: string;

    @IsNotEmpty()
    @IsString()
    @ApiProperty()
    password: string;

    @ApiProperty({ enum: ['ORGANIZER', 'ADMIN', 'SPONSOR'] })
    @IsEnum(UserRole, {
        message: `Invalid value for 'role'. Acceptable values are: ${Object.values(UserRole)}`
    })
    role: UserRole;
}
