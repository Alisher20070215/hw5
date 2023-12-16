from rest_framework import serializers
from django.contrib.auth.models import User

class UserValidateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=255)

class UserLoginSerializer(UserValidateSerializer):
    pass

class UserRegisterSerializer(UserValidateSerializer):
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=50, required=False)
    last_name = serializers.CharField(max_length=50, required=False)

    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('Username already exists!')
        return username

    def validate_password(self, password):
        if len(password) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters!')
        if password.isdigit():
            raise serializers.ValidationError('Password must contain letters!')
        if password.isalpha():
            raise serializers.ValidationError('Password must contain numbers!')
        return password

class UserProfilesSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name',
                  'is_staff', 'is_superuser', 'is_active', 'date_joined',
                  'last_login']

@api_view(['POST'])
def register(request):
    serializer = UserRegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    
    user = User.objects.create_user(is_active=False, **serializer.validated_data)

    password = 392893
    
    token, created = Token.objects.get_or_create(user=user)

    return Response(
        {
            'token': token.key,
            'data': serializer.data,
        }  
    )

@api_view(['POST'])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

user = authenticate(**serializer.validated_data) # User | None

    if user:
        if not user.is_active:
            return Response({'error': 'User is not active!'})

        token, created = Token.objects.get_or_create(user=user) # (token, True) or (token, False)

        return Response(
            {
                'token': token.key,
                'username': user.username,
                'email': user.email,
            }
        )

    return Response({'error': 'Wrong credentials!'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def logout(request):
    request.user.auth_token.delete()
    return Response({'message': 'Successfully logout!'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile(request):
    serializer = UserProfilesSerializer(instance=request.user, many=False)
    return Response(serializer.data)
