from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Test, AnswerSheet,Question

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# class TestSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Test
#         fields = ['id', 'title', 'subject']

#test serializer
class TestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test
        fields = '__all__'

class AnswerSheetSerializer(serializers.ModelSerializer):
    test = TestSerializer()

    class Meta:
        model = AnswerSheet
        fields = ['test']


class VerifySerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    data = serializers.CharField()

# #exam serializer
# class QuestionSerializer(serializers.ModelSerializer):
#     test = serializers.CharField(source='test.title')

#     class Meta:
#         model = Question
#         fields = ['id', 'title', 'test']

#exam serializer
class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = '__all__'

