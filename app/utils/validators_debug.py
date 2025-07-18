"""
DEBUG VERSION - Shows real validation errors instead of masking them
"""
from functools import wraps
from typing import Dict, Any, Optional

from flask import request
from marshmallow import Schema, fields, validate, ValidationError, post_load
import re
import traceback
import structlog

from app.utils.error_handlers import APIException, ErrorCodes

logger = structlog.get_logger()

# Import all the schema classes from original validators
from app.utils.validators import (
    UserRegistrationSchema, UserLoginSchema, PasswordResetRequestSchema,
    PasswordResetSchema, WebsiteCreateSchema, WebsiteUpdateSchema,
    AnalyticsEventSchema, AnalyticsQuerySchema, PaginationSchema,
    PaymentMethodSchema, PayoutRequestSchema, AdminUserUpdateSchema,
    ContactFormSchema
)

def validate_json(schema_class: Schema):
    """
    DEBUG VERSION - Shows actual errors instead of masking them
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get JSON data
                json_data = request.get_json()
                if json_data is None:
                    logger.error("No JSON data in request")
                    raise APIException(
                        ErrorCodes.VALIDATION_ERROR,
                        "Request must contain valid JSON",
                        400
                    )
                
                logger.info("Received JSON data", data=json_data)
                
                # Validate data
                schema = schema_class()
                logger.info("Created schema", schema_class=schema_class.__name__)
                
                validated_data = schema.load(json_data)
                logger.info("Validation successful", validated_data=validated_data)
                
                # Pass validated data to the function
                return f(validated_data, *args, **kwargs)
                
            except ValidationError as err:
                logger.error("Validation error", errors=err.messages)
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "Request validation failed",
                    422,
                    {"validation_errors": err.messages}
                )
            except APIException:
                raise
            except Exception as e:
                # LOG THE ACTUAL ERROR INSTEAD OF MASKING IT
                logger.error("REAL VALIDATION ERROR", 
                           error=str(e), 
                           traceback=traceback.format_exc(),
                           json_data=json_data if 'json_data' in locals() else None)
                
                # Return the actual error for debugging
                raise APIException(
                    ErrorCodes.INTERNAL_ERROR,
                    f"REAL ERROR: {str(e)}",
                    500
                )
        
        return decorated_function
    return decorator

