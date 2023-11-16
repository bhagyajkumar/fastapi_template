from fastapi import APIRouter
from ..models.auth import LoginInputForm, LoginTokens, SignupInputForm


router = APIRouter(
    prefix="/auth"
)

@router.post("/signup")
def register_user(user_details:SignupInputForm):
    user_details.save()
    return {
        "detail" : "Signup Successfull"
    }

@router.post("/login", response_model=LoginTokens)
def login(item:LoginInputForm):
    tokens = item.get_jwt_tokens()
    return tokens
