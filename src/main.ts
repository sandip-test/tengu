import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptor/response.interceptor';
import { UnprocessableEntityException, ValidationPipe } from '@nestjs/common';
import { Logger } from './lib/logger';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

import { APP_CONFIG } from './config';
import * as express from 'express';
import * as fs from 'fs';
import * as path from 'path';

import { apiReference } from '@scalar/nestjs-api-reference';

async function bootstrap() {
  const PORT = process.env.PORT || 5000;
  const logger = new Logger('Bootstrap');
  const app = (await NestFactory.create(AppModule)).setGlobalPrefix('api/v1');
  logger.info(`Starting server... on port ${PORT}`);

  /**
   * Serve static files from public folder.
   */
  app.use(express.static(path.join('public')));

  /**
   * Enable Swagger if specified in env.
   */
  if (process.env.ENABLE_SWAGGER == 'true') {
    logger.info('Enabling Swagger');
    const config = new DocumentBuilder()
      .setTitle(`API Docs | ${APP_CONFIG.NAME} | ${APP_CONFIG.CURRENT_VERSION}`)
      .setVersion(APP_CONFIG.CURRENT_VERSION)
      .addSecurity('jwt-auth', {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          'Use the `Authorization` header with `Bearer <token>` format.',
      })
      .build();

    const swaggerFilename = 'swagger-spec.json';

    const document = SwaggerModule.createDocument(app, config);
    // Save JSON spec to serve in public folder

    fs.writeFileSync(
      path.join(`public/${swaggerFilename}`),
      JSON.stringify(document),
    );

    const swaggerPath = process.env.SWAGGER_PATH ?? '/docs';

    app.use(
      swaggerPath,
      apiReference({
        theme: 'bluePlanet',
        title: `${APP_CONFIG.NAME} | API  Documentation`,
        cdn: 'https://cdn.jsdelivr.net/npm/@scalar/api-reference@latest',
        url: '/swagger-spec.json',
      }),
    );
  } else {
    logger.log('Skipping swagger docs initialization!');
  }

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

  await app.listen(PORT);
}
bootstrap();
