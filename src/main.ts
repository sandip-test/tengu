import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptor/response.interceptor';
import { UnprocessableEntityException, ValidationPipe } from '@nestjs/common';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);

  /**
   * Global validation pipe for DTOs.
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strip unwanted properties
      transform: true, // Automatically transform payloads to DTO instances,

      /**
       * Custom exception factory to return a single error message with all the errors.
       */
      exceptionFactory(errors) {
        const errorMessages = errors
          .map((error) => {
            return Object.values(error.constraints ?? {});
          })
          .flat()
          .map((message) => message?.trim());

        throw new UnprocessableEntityException({
          message: errorMessages.join(', '),
          error: errorMessages,
        });
      },
    }),
  );

  /**
   * Global response interceptor to format responses as `application/json`.
   */
  app.useGlobalInterceptors(new ResponseInterceptor());
}
bootstrap();
