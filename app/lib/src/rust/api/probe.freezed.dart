// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'probe.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$ProbeChoice {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ProbeChoice);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'ProbeChoice()';
}


}

/// @nodoc
class $ProbeChoiceCopyWith<$Res>  {
$ProbeChoiceCopyWith(ProbeChoice _, $Res Function(ProbeChoice) __);
}


/// Adds pattern-matching-related methods to [ProbeChoice].
extension ProbeChoicePatterns on ProbeChoice {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( ProbeChoice_First value)?  first,TResult Function( ProbeChoice_Second value)?  second,required TResult orElse(),}){
final _that = this;
switch (_that) {
case ProbeChoice_First() when first != null:
return first(_that);case ProbeChoice_Second() when second != null:
return second(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( ProbeChoice_First value)  first,required TResult Function( ProbeChoice_Second value)  second,}){
final _that = this;
switch (_that) {
case ProbeChoice_First():
return first(_that);case ProbeChoice_Second():
return second(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( ProbeChoice_First value)?  first,TResult? Function( ProbeChoice_Second value)?  second,}){
final _that = this;
switch (_that) {
case ProbeChoice_First() when first != null:
return first(_that);case ProbeChoice_Second() when second != null:
return second(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  first,TResult Function( String detail)?  second,required TResult orElse(),}) {final _that = this;
switch (_that) {
case ProbeChoice_First() when first != null:
return first();case ProbeChoice_Second() when second != null:
return second(_that.detail);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  first,required TResult Function( String detail)  second,}) {final _that = this;
switch (_that) {
case ProbeChoice_First():
return first();case ProbeChoice_Second():
return second(_that.detail);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  first,TResult? Function( String detail)?  second,}) {final _that = this;
switch (_that) {
case ProbeChoice_First() when first != null:
return first();case ProbeChoice_Second() when second != null:
return second(_that.detail);case _:
  return null;

}
}

}

/// @nodoc


class ProbeChoice_First extends ProbeChoice {
  const ProbeChoice_First(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ProbeChoice_First);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'ProbeChoice.first()';
}


}




/// @nodoc


class ProbeChoice_Second extends ProbeChoice {
  const ProbeChoice_Second({required this.detail}): super._();
  

 final  String detail;

/// Create a copy of ProbeChoice
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$ProbeChoice_SecondCopyWith<ProbeChoice_Second> get copyWith => _$ProbeChoice_SecondCopyWithImpl<ProbeChoice_Second>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is ProbeChoice_Second&&(identical(other.detail, detail) || other.detail == detail));
}


@override
int get hashCode => Object.hash(runtimeType,detail);

@override
String toString() {
  return 'ProbeChoice.second(detail: $detail)';
}


}

/// @nodoc
abstract mixin class $ProbeChoice_SecondCopyWith<$Res> implements $ProbeChoiceCopyWith<$Res> {
  factory $ProbeChoice_SecondCopyWith(ProbeChoice_Second value, $Res Function(ProbeChoice_Second) _then) = _$ProbeChoice_SecondCopyWithImpl;
@useResult
$Res call({
 String detail
});




}
/// @nodoc
class _$ProbeChoice_SecondCopyWithImpl<$Res>
    implements $ProbeChoice_SecondCopyWith<$Res> {
  _$ProbeChoice_SecondCopyWithImpl(this._self, this._then);

  final ProbeChoice_Second _self;
  final $Res Function(ProbeChoice_Second) _then;

/// Create a copy of ProbeChoice
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? detail = null,}) {
  return _then(ProbeChoice_Second(
detail: null == detail ? _self.detail : detail // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
