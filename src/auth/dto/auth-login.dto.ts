import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';
import { Transform } from 'class-transformer';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';

export class AuthLoginDto {
  @ApiProperty({ example: 'mohamad123', type: String })
  @Transform(lowerCaseTransformer)
  @IsNotEmpty()
  @IsString()
  @Length(4, 20, { message: 'Username must be between 4 and 20 characters' })
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username must contain only letters, numbers, and underscores',
  })
  username: string;

  @ApiProperty()
  @IsNotEmpty()
  password: string;
}
