"""
Fixed validation system compatible with existing backend modules.
Simplified to work with User model, error handlers, and database structure.
"""
from functools import wraps
from typing import Dict, Any

from flask import request
from marshmallow import Schema, fields, validate, ValidationError
import structlog

from app.utils.error_handlers import APIException, ErrorCodes

logger = structlog.get_logger()


class BaseSchema(Schema):
    """Base schema with common validation methods."""
    pass


# Simplified EmailField that works with your system
class EmailField(fields.Email):
    """Simple email field without complex validation that was breaking."""
    pass


# Simplified PasswordField that works with your system  
class PasswordField(fields.String):
    """Simple password field with basic validation."""
    
    def __init__(self, **kwargs):
        super().__init__(validate=validate.Length(min=6), **kwargs)


# Authentication Schemas - Compatible with your User model
class UserRegistrationSchema(BaseSchema):
    """Schema for user registration - matches your User model fields."""
    
    email = EmailField(required=True)
    password = PasswordField(required=True)
    first_name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    last_name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    company = fields.Str(validate=validate.Length(max=255), missing=None)


class UserLoginSchema(BaseSchema):
    """Schema for user login - matches your auth system."""
    
    email = EmailField(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=1))


# Simplified validation decorator that works with your error system
def validate_json(schema_class: Schema):
    """
    Validation decorator compatible with your APIException and ErrorCodes.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get JSON data
                json_data = request.get_json()
                if json_data is None:
                    raise APIException(
                        ErrorCodes.VALIDATION_ERROR,
                        "Request must contain valid JSON",
                        400
                    )
                
                # Validate data using the schema
                schema = schema_class()
                validated_data = schema.load(json_data)
                
                # Pass validated data to the function
                return f(validated_data, *args, **kwargs)
                
            except ValidationError as err:
                # Handle Marshmallow validation errors
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "Request validation failed",
                    422,
                    {"validation_errors": err.messages}
                )
            except APIException:
                # Re-raise API exceptions as-is
                raise
            except Exception as e:
                # Log the error but provide a clean response
                logger.error("Validation processing error", error=str(e))
                raise APIException(
                    ErrorCodes.INTERNAL_ERROR,
                    "Validation processing failed",
                    500
                )
        
        return decorated_function
    return decorator

