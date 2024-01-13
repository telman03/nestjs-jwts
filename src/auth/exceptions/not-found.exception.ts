// not-found.exception.ts
import { NotFoundException as NestNotFoundException } from '@nestjs/common';

export class NotFoundException extends NestNotFoundException {
  constructor(message: string = 'Not Found') {
    super(message);
  }
}
