// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'protocol.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$IncomingDto {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is IncomingDto);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'IncomingDto()';
}


}

/// @nodoc
class $IncomingDtoCopyWith<$Res>  {
$IncomingDtoCopyWith(IncomingDto _, $Res Function(IncomingDto) __);
}


/// Adds pattern-matching-related methods to [IncomingDto].
extension IncomingDtoPatterns on IncomingDto {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( IncomingDto_Ack value)?  ack,TResult Function( IncomingDto_Error value)?  error,TResult Function( IncomingDto_State value)?  state,TResult Function( IncomingDto_Stats value)?  stats,required TResult orElse(),}){
final _that = this;
switch (_that) {
case IncomingDto_Ack() when ack != null:
return ack(_that);case IncomingDto_Error() when error != null:
return error(_that);case IncomingDto_State() when state != null:
return state(_that);case IncomingDto_Stats() when stats != null:
return stats(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( IncomingDto_Ack value)  ack,required TResult Function( IncomingDto_Error value)  error,required TResult Function( IncomingDto_State value)  state,required TResult Function( IncomingDto_Stats value)  stats,}){
final _that = this;
switch (_that) {
case IncomingDto_Ack():
return ack(_that);case IncomingDto_Error():
return error(_that);case IncomingDto_State():
return state(_that);case IncomingDto_Stats():
return stats(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( IncomingDto_Ack value)?  ack,TResult? Function( IncomingDto_Error value)?  error,TResult? Function( IncomingDto_State value)?  state,TResult? Function( IncomingDto_Stats value)?  stats,}){
final _that = this;
switch (_that) {
case IncomingDto_Ack() when ack != null:
return ack(_that);case IncomingDto_Error() when error != null:
return error(_that);case IncomingDto_State() when state != null:
return state(_that);case IncomingDto_Stats() when stats != null:
return stats(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt id)?  ack,TResult Function( BigInt id,  ErrorKindDto kind,  String message)?  error,TResult Function( String state)?  state,TResult Function( BigInt bytesUp,  BigInt bytesDown,  int activeFlows,  BigInt flowsFailed,  BigInt dnsQueries)?  stats,required TResult orElse(),}) {final _that = this;
switch (_that) {
case IncomingDto_Ack() when ack != null:
return ack(_that.id);case IncomingDto_Error() when error != null:
return error(_that.id,_that.kind,_that.message);case IncomingDto_State() when state != null:
return state(_that.state);case IncomingDto_Stats() when stats != null:
return stats(_that.bytesUp,_that.bytesDown,_that.activeFlows,_that.flowsFailed,_that.dnsQueries);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt id)  ack,required TResult Function( BigInt id,  ErrorKindDto kind,  String message)  error,required TResult Function( String state)  state,required TResult Function( BigInt bytesUp,  BigInt bytesDown,  int activeFlows,  BigInt flowsFailed,  BigInt dnsQueries)  stats,}) {final _that = this;
switch (_that) {
case IncomingDto_Ack():
return ack(_that.id);case IncomingDto_Error():
return error(_that.id,_that.kind,_that.message);case IncomingDto_State():
return state(_that.state);case IncomingDto_Stats():
return stats(_that.bytesUp,_that.bytesDown,_that.activeFlows,_that.flowsFailed,_that.dnsQueries);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt id)?  ack,TResult? Function( BigInt id,  ErrorKindDto kind,  String message)?  error,TResult? Function( String state)?  state,TResult? Function( BigInt bytesUp,  BigInt bytesDown,  int activeFlows,  BigInt flowsFailed,  BigInt dnsQueries)?  stats,}) {final _that = this;
switch (_that) {
case IncomingDto_Ack() when ack != null:
return ack(_that.id);case IncomingDto_Error() when error != null:
return error(_that.id,_that.kind,_that.message);case IncomingDto_State() when state != null:
return state(_that.state);case IncomingDto_Stats() when stats != null:
return stats(_that.bytesUp,_that.bytesDown,_that.activeFlows,_that.flowsFailed,_that.dnsQueries);case _:
  return null;

}
}

}

/// @nodoc


class IncomingDto_Ack extends IncomingDto {
  const IncomingDto_Ack({required this.id}): super._();
  

 final  BigInt id;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$IncomingDto_AckCopyWith<IncomingDto_Ack> get copyWith => _$IncomingDto_AckCopyWithImpl<IncomingDto_Ack>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is IncomingDto_Ack&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,id);

@override
String toString() {
  return 'IncomingDto.ack(id: $id)';
}


}

/// @nodoc
abstract mixin class $IncomingDto_AckCopyWith<$Res> implements $IncomingDtoCopyWith<$Res> {
  factory $IncomingDto_AckCopyWith(IncomingDto_Ack value, $Res Function(IncomingDto_Ack) _then) = _$IncomingDto_AckCopyWithImpl;
@useResult
$Res call({
 BigInt id
});




}
/// @nodoc
class _$IncomingDto_AckCopyWithImpl<$Res>
    implements $IncomingDto_AckCopyWith<$Res> {
  _$IncomingDto_AckCopyWithImpl(this._self, this._then);

  final IncomingDto_Ack _self;
  final $Res Function(IncomingDto_Ack) _then;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? id = null,}) {
  return _then(IncomingDto_Ack(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class IncomingDto_Error extends IncomingDto {
  const IncomingDto_Error({required this.id, required this.kind, required this.message}): super._();
  

 final  BigInt id;
 final  ErrorKindDto kind;
 final  String message;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$IncomingDto_ErrorCopyWith<IncomingDto_Error> get copyWith => _$IncomingDto_ErrorCopyWithImpl<IncomingDto_Error>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is IncomingDto_Error&&(identical(other.id, id) || other.id == id)&&(identical(other.kind, kind) || other.kind == kind)&&(identical(other.message, message) || other.message == message));
}


@override
int get hashCode => Object.hash(runtimeType,id,kind,message);

@override
String toString() {
  return 'IncomingDto.error(id: $id, kind: $kind, message: $message)';
}


}

/// @nodoc
abstract mixin class $IncomingDto_ErrorCopyWith<$Res> implements $IncomingDtoCopyWith<$Res> {
  factory $IncomingDto_ErrorCopyWith(IncomingDto_Error value, $Res Function(IncomingDto_Error) _then) = _$IncomingDto_ErrorCopyWithImpl;
@useResult
$Res call({
 BigInt id, ErrorKindDto kind, String message
});




}
/// @nodoc
class _$IncomingDto_ErrorCopyWithImpl<$Res>
    implements $IncomingDto_ErrorCopyWith<$Res> {
  _$IncomingDto_ErrorCopyWithImpl(this._self, this._then);

  final IncomingDto_Error _self;
  final $Res Function(IncomingDto_Error) _then;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? id = null,Object? kind = null,Object? message = null,}) {
  return _then(IncomingDto_Error(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,kind: null == kind ? _self.kind : kind // ignore: cast_nullable_to_non_nullable
as ErrorKindDto,message: null == message ? _self.message : message // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class IncomingDto_State extends IncomingDto {
  const IncomingDto_State({required this.state}): super._();
  

 final  String state;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$IncomingDto_StateCopyWith<IncomingDto_State> get copyWith => _$IncomingDto_StateCopyWithImpl<IncomingDto_State>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is IncomingDto_State&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,state);

@override
String toString() {
  return 'IncomingDto.state(state: $state)';
}


}

/// @nodoc
abstract mixin class $IncomingDto_StateCopyWith<$Res> implements $IncomingDtoCopyWith<$Res> {
  factory $IncomingDto_StateCopyWith(IncomingDto_State value, $Res Function(IncomingDto_State) _then) = _$IncomingDto_StateCopyWithImpl;
@useResult
$Res call({
 String state
});




}
/// @nodoc
class _$IncomingDto_StateCopyWithImpl<$Res>
    implements $IncomingDto_StateCopyWith<$Res> {
  _$IncomingDto_StateCopyWithImpl(this._self, this._then);

  final IncomingDto_State _self;
  final $Res Function(IncomingDto_State) _then;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? state = null,}) {
  return _then(IncomingDto_State(
state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class IncomingDto_Stats extends IncomingDto {
  const IncomingDto_Stats({required this.bytesUp, required this.bytesDown, required this.activeFlows, required this.flowsFailed, required this.dnsQueries}): super._();
  

 final  BigInt bytesUp;
 final  BigInt bytesDown;
 final  int activeFlows;
 final  BigInt flowsFailed;
 final  BigInt dnsQueries;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$IncomingDto_StatsCopyWith<IncomingDto_Stats> get copyWith => _$IncomingDto_StatsCopyWithImpl<IncomingDto_Stats>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is IncomingDto_Stats&&(identical(other.bytesUp, bytesUp) || other.bytesUp == bytesUp)&&(identical(other.bytesDown, bytesDown) || other.bytesDown == bytesDown)&&(identical(other.activeFlows, activeFlows) || other.activeFlows == activeFlows)&&(identical(other.flowsFailed, flowsFailed) || other.flowsFailed == flowsFailed)&&(identical(other.dnsQueries, dnsQueries) || other.dnsQueries == dnsQueries));
}


@override
int get hashCode => Object.hash(runtimeType,bytesUp,bytesDown,activeFlows,flowsFailed,dnsQueries);

@override
String toString() {
  return 'IncomingDto.stats(bytesUp: $bytesUp, bytesDown: $bytesDown, activeFlows: $activeFlows, flowsFailed: $flowsFailed, dnsQueries: $dnsQueries)';
}


}

/// @nodoc
abstract mixin class $IncomingDto_StatsCopyWith<$Res> implements $IncomingDtoCopyWith<$Res> {
  factory $IncomingDto_StatsCopyWith(IncomingDto_Stats value, $Res Function(IncomingDto_Stats) _then) = _$IncomingDto_StatsCopyWithImpl;
@useResult
$Res call({
 BigInt bytesUp, BigInt bytesDown, int activeFlows, BigInt flowsFailed, BigInt dnsQueries
});




}
/// @nodoc
class _$IncomingDto_StatsCopyWithImpl<$Res>
    implements $IncomingDto_StatsCopyWith<$Res> {
  _$IncomingDto_StatsCopyWithImpl(this._self, this._then);

  final IncomingDto_Stats _self;
  final $Res Function(IncomingDto_Stats) _then;

/// Create a copy of IncomingDto
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? bytesUp = null,Object? bytesDown = null,Object? activeFlows = null,Object? flowsFailed = null,Object? dnsQueries = null,}) {
  return _then(IncomingDto_Stats(
bytesUp: null == bytesUp ? _self.bytesUp : bytesUp // ignore: cast_nullable_to_non_nullable
as BigInt,bytesDown: null == bytesDown ? _self.bytesDown : bytesDown // ignore: cast_nullable_to_non_nullable
as BigInt,activeFlows: null == activeFlows ? _self.activeFlows : activeFlows // ignore: cast_nullable_to_non_nullable
as int,flowsFailed: null == flowsFailed ? _self.flowsFailed : flowsFailed // ignore: cast_nullable_to_non_nullable
as BigInt,dnsQueries: null == dnsQueries ? _self.dnsQueries : dnsQueries // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc
mixin _$RequestDto {

 BigInt get id;
/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RequestDtoCopyWith<RequestDto> get copyWith => _$RequestDtoCopyWithImpl<RequestDto>(this as RequestDto, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RequestDto&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,id);

@override
String toString() {
  return 'RequestDto(id: $id)';
}


}

/// @nodoc
abstract mixin class $RequestDtoCopyWith<$Res>  {
  factory $RequestDtoCopyWith(RequestDto value, $Res Function(RequestDto) _then) = _$RequestDtoCopyWithImpl;
@useResult
$Res call({
 BigInt id
});




}
/// @nodoc
class _$RequestDtoCopyWithImpl<$Res>
    implements $RequestDtoCopyWith<$Res> {
  _$RequestDtoCopyWithImpl(this._self, this._then);

  final RequestDto _self;
  final $Res Function(RequestDto) _then;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? id = null,}) {
  return _then(_self.copyWith(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}

}


/// Adds pattern-matching-related methods to [RequestDto].
extension RequestDtoPatterns on RequestDto {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( RequestDto_Hello value)?  hello,TResult Function( RequestDto_Connect value)?  connect,TResult Function( RequestDto_Disconnect value)?  disconnect,TResult Function( RequestDto_GetStatus value)?  getStatus,required TResult orElse(),}){
final _that = this;
switch (_that) {
case RequestDto_Hello() when hello != null:
return hello(_that);case RequestDto_Connect() when connect != null:
return connect(_that);case RequestDto_Disconnect() when disconnect != null:
return disconnect(_that);case RequestDto_GetStatus() when getStatus != null:
return getStatus(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( RequestDto_Hello value)  hello,required TResult Function( RequestDto_Connect value)  connect,required TResult Function( RequestDto_Disconnect value)  disconnect,required TResult Function( RequestDto_GetStatus value)  getStatus,}){
final _that = this;
switch (_that) {
case RequestDto_Hello():
return hello(_that);case RequestDto_Connect():
return connect(_that);case RequestDto_Disconnect():
return disconnect(_that);case RequestDto_GetStatus():
return getStatus(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( RequestDto_Hello value)?  hello,TResult? Function( RequestDto_Connect value)?  connect,TResult? Function( RequestDto_Disconnect value)?  disconnect,TResult? Function( RequestDto_GetStatus value)?  getStatus,}){
final _that = this;
switch (_that) {
case RequestDto_Hello() when hello != null:
return hello(_that);case RequestDto_Connect() when connect != null:
return connect(_that);case RequestDto_Disconnect() when disconnect != null:
return disconnect(_that);case RequestDto_GetStatus() when getStatus != null:
return getStatus(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt id)?  hello,TResult Function( BigInt id,  ConnectParamsDto params)?  connect,TResult Function( BigInt id)?  disconnect,TResult Function( BigInt id)?  getStatus,required TResult orElse(),}) {final _that = this;
switch (_that) {
case RequestDto_Hello() when hello != null:
return hello(_that.id);case RequestDto_Connect() when connect != null:
return connect(_that.id,_that.params);case RequestDto_Disconnect() when disconnect != null:
return disconnect(_that.id);case RequestDto_GetStatus() when getStatus != null:
return getStatus(_that.id);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt id)  hello,required TResult Function( BigInt id,  ConnectParamsDto params)  connect,required TResult Function( BigInt id)  disconnect,required TResult Function( BigInt id)  getStatus,}) {final _that = this;
switch (_that) {
case RequestDto_Hello():
return hello(_that.id);case RequestDto_Connect():
return connect(_that.id,_that.params);case RequestDto_Disconnect():
return disconnect(_that.id);case RequestDto_GetStatus():
return getStatus(_that.id);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt id)?  hello,TResult? Function( BigInt id,  ConnectParamsDto params)?  connect,TResult? Function( BigInt id)?  disconnect,TResult? Function( BigInt id)?  getStatus,}) {final _that = this;
switch (_that) {
case RequestDto_Hello() when hello != null:
return hello(_that.id);case RequestDto_Connect() when connect != null:
return connect(_that.id,_that.params);case RequestDto_Disconnect() when disconnect != null:
return disconnect(_that.id);case RequestDto_GetStatus() when getStatus != null:
return getStatus(_that.id);case _:
  return null;

}
}

}

/// @nodoc


class RequestDto_Hello extends RequestDto {
  const RequestDto_Hello({required this.id}): super._();
  

@override final  BigInt id;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RequestDto_HelloCopyWith<RequestDto_Hello> get copyWith => _$RequestDto_HelloCopyWithImpl<RequestDto_Hello>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RequestDto_Hello&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,id);

@override
String toString() {
  return 'RequestDto.hello(id: $id)';
}


}

/// @nodoc
abstract mixin class $RequestDto_HelloCopyWith<$Res> implements $RequestDtoCopyWith<$Res> {
  factory $RequestDto_HelloCopyWith(RequestDto_Hello value, $Res Function(RequestDto_Hello) _then) = _$RequestDto_HelloCopyWithImpl;
@override @useResult
$Res call({
 BigInt id
});




}
/// @nodoc
class _$RequestDto_HelloCopyWithImpl<$Res>
    implements $RequestDto_HelloCopyWith<$Res> {
  _$RequestDto_HelloCopyWithImpl(this._self, this._then);

  final RequestDto_Hello _self;
  final $Res Function(RequestDto_Hello) _then;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,}) {
  return _then(RequestDto_Hello(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class RequestDto_Connect extends RequestDto {
  const RequestDto_Connect({required this.id, required this.params}): super._();
  

@override final  BigInt id;
 final  ConnectParamsDto params;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RequestDto_ConnectCopyWith<RequestDto_Connect> get copyWith => _$RequestDto_ConnectCopyWithImpl<RequestDto_Connect>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RequestDto_Connect&&(identical(other.id, id) || other.id == id)&&(identical(other.params, params) || other.params == params));
}


@override
int get hashCode => Object.hash(runtimeType,id,params);

@override
String toString() {
  return 'RequestDto.connect(id: $id, params: $params)';
}


}

/// @nodoc
abstract mixin class $RequestDto_ConnectCopyWith<$Res> implements $RequestDtoCopyWith<$Res> {
  factory $RequestDto_ConnectCopyWith(RequestDto_Connect value, $Res Function(RequestDto_Connect) _then) = _$RequestDto_ConnectCopyWithImpl;
@override @useResult
$Res call({
 BigInt id, ConnectParamsDto params
});




}
/// @nodoc
class _$RequestDto_ConnectCopyWithImpl<$Res>
    implements $RequestDto_ConnectCopyWith<$Res> {
  _$RequestDto_ConnectCopyWithImpl(this._self, this._then);

  final RequestDto_Connect _self;
  final $Res Function(RequestDto_Connect) _then;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,Object? params = null,}) {
  return _then(RequestDto_Connect(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,params: null == params ? _self.params : params // ignore: cast_nullable_to_non_nullable
as ConnectParamsDto,
  ));
}


}

/// @nodoc


class RequestDto_Disconnect extends RequestDto {
  const RequestDto_Disconnect({required this.id}): super._();
  

@override final  BigInt id;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RequestDto_DisconnectCopyWith<RequestDto_Disconnect> get copyWith => _$RequestDto_DisconnectCopyWithImpl<RequestDto_Disconnect>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RequestDto_Disconnect&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,id);

@override
String toString() {
  return 'RequestDto.disconnect(id: $id)';
}


}

/// @nodoc
abstract mixin class $RequestDto_DisconnectCopyWith<$Res> implements $RequestDtoCopyWith<$Res> {
  factory $RequestDto_DisconnectCopyWith(RequestDto_Disconnect value, $Res Function(RequestDto_Disconnect) _then) = _$RequestDto_DisconnectCopyWithImpl;
@override @useResult
$Res call({
 BigInt id
});




}
/// @nodoc
class _$RequestDto_DisconnectCopyWithImpl<$Res>
    implements $RequestDto_DisconnectCopyWith<$Res> {
  _$RequestDto_DisconnectCopyWithImpl(this._self, this._then);

  final RequestDto_Disconnect _self;
  final $Res Function(RequestDto_Disconnect) _then;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,}) {
  return _then(RequestDto_Disconnect(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class RequestDto_GetStatus extends RequestDto {
  const RequestDto_GetStatus({required this.id}): super._();
  

@override final  BigInt id;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$RequestDto_GetStatusCopyWith<RequestDto_GetStatus> get copyWith => _$RequestDto_GetStatusCopyWithImpl<RequestDto_GetStatus>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is RequestDto_GetStatus&&(identical(other.id, id) || other.id == id));
}


@override
int get hashCode => Object.hash(runtimeType,id);

@override
String toString() {
  return 'RequestDto.getStatus(id: $id)';
}


}

/// @nodoc
abstract mixin class $RequestDto_GetStatusCopyWith<$Res> implements $RequestDtoCopyWith<$Res> {
  factory $RequestDto_GetStatusCopyWith(RequestDto_GetStatus value, $Res Function(RequestDto_GetStatus) _then) = _$RequestDto_GetStatusCopyWithImpl;
@override @useResult
$Res call({
 BigInt id
});




}
/// @nodoc
class _$RequestDto_GetStatusCopyWithImpl<$Res>
    implements $RequestDto_GetStatusCopyWith<$Res> {
  _$RequestDto_GetStatusCopyWithImpl(this._self, this._then);

  final RequestDto_GetStatus _self;
  final $Res Function(RequestDto_GetStatus) _then;

/// Create a copy of RequestDto
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? id = null,}) {
  return _then(RequestDto_GetStatus(
id: null == id ? _self.id : id // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

// dart format on
